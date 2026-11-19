// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text;

namespace Axiom.Infrastructure.Linux.Bpf;

/// <summary>
/// One line of <c>/proc/self/mountinfo</c> (proc(5)): field 3 <c>MAJ:MIN</c> is the superblock
/// <c>s_dev</c> — exactly what the BPF program reads from <c>inode->i_sb->s_dev</c> — while
/// <c>stat</c>'s <c>st_dev</c> may differ (btrfs reports a per-subvolume anonymous device).
/// </summary>
public sealed record MountInfoEntry(int MountId, int ParentId, uint DevMajor, uint DevMinor, string Root, string MountPoint, string FsType, string Source)
{
    public string Dev => string.Create(CultureInfo.InvariantCulture, $"{DevMajor}:{DevMinor}");
}

/// <summary>Parsed mountinfo of one mount namespace with a longest-prefix lookup.</summary>
public sealed class MountInfoTable
{
    private MountInfoTable(IReadOnlyList<MountInfoEntry> entries) => Entries = entries;

    /// <summary>Entries in file order (later entries are mounted on top of earlier ones).</summary>
    public IReadOnlyList<MountInfoEntry> Entries { get; }

    /// <summary>Parses mountinfo text; malformed lines are skipped, null/empty gives an empty table.</summary>
    public static MountInfoTable Parse(string? text)
    {
        var entries = new List<MountInfoEntry>();
        foreach (var line in (text ?? string.Empty).Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (TryParseLine(line, out var entry))
            {
                entries.Add(entry);
            }
        }

        return new MountInfoTable(entries);
    }

    /// <summary>
    /// The mount an absolute, symlink-free path lives on: the entry whose mount point is the longest
    /// whole-component prefix of <paramref name="absolutePath"/>; among equal mount points the last
    /// line wins (it is mounted over the earlier ones). Null for relative paths or no match.
    /// </summary>
    public MountInfoEntry? Find(string absolutePath)
    {
        ArgumentNullException.ThrowIfNull(absolutePath);
        if (!absolutePath.StartsWith('/'))
        {
            return null;
        }

        MountInfoEntry? best = null;
        foreach (var entry in Entries)
        {
            if (Covers(entry.MountPoint, absolutePath) && (best is null || entry.MountPoint.Length >= best.MountPoint.Length))
            {
                best = entry;
            }
        }

        return best;
    }

    /// <summary>Decodes the kernel's octal escapes (<c>\040</c> space, <c>\011</c> tab, <c>\012</c> newline, <c>\134</c> backslash).</summary>
    public static string Unescape(string field)
    {
        ArgumentNullException.ThrowIfNull(field);
        if (!field.Contains('\\', StringComparison.Ordinal))
        {
            return field;
        }

        var builder = new StringBuilder(field.Length);
        for (var i = 0; i < field.Length; i++)
        {
            if (field[i] == '\\' && IsOctal(field, i + 1))
            {
                builder.Append((char)(((field[i + 1] - '0') * 64) + ((field[i + 2] - '0') * 8) + (field[i + 3] - '0')));
                i += 3;
            }
            else
            {
                builder.Append(field[i]);
            }
        }

        return builder.ToString();
    }

    private static bool IsOctal(string text, int start) =>
        start + 2 < text.Length && text[start] is >= '0' and <= '3' && text[start + 1] is >= '0' and <= '7' && text[start + 2] is >= '0' and <= '7';

    private static bool Covers(string mountPoint, string path) =>
        mountPoint == "/" ||
        string.Equals(path, mountPoint, StringComparison.Ordinal) ||
        (path.StartsWith(mountPoint, StringComparison.Ordinal) && path[mountPoint.Length] == '/');

    // 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
    private static bool TryParseLine(string line, out MountInfoEntry entry)
    {
        entry = null!;
        var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var separator = fields.Length < 7 ? -1 : Array.IndexOf(fields, "-", 6);
        if (separator < 0 || separator + 2 >= fields.Length)
        {
            return false;
        }

        var dev = fields[2].Split(':');
        if (dev.Length != 2 ||
            !int.TryParse(fields[0], NumberStyles.None, CultureInfo.InvariantCulture, out var id) ||
            !int.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var parent) ||
            !uint.TryParse(dev[0], NumberStyles.None, CultureInfo.InvariantCulture, out var major) ||
            !uint.TryParse(dev[1], NumberStyles.None, CultureInfo.InvariantCulture, out var minor) ||
            !fields[4].StartsWith('/'))
        {
            return false;
        }

        entry = new MountInfoEntry(id, parent, major, minor, Unescape(fields[3]), Unescape(fields[4]), Unescape(fields[separator + 1]), Unescape(fields[separator + 2]));
        return true;
    }
}

/// <summary>Outcome of deriving a BPF exe key: the key, or null with the reason the rule stays nft-only.</summary>
public sealed record BpfExeKeyResolution(BpfInode? Key, string Detail, MountInfoEntry? Mount);

/// <summary>
/// Derives the exe-verdict key the kernel side will compute (docs/LINUX_EBPF.md §3.1): device =
/// superblock <c>s_dev</c> from mountinfo field 3 of the mount the canonical path lives on, inode =
/// <c>stat</c>'s <c>st_ino</c>. The stat device is a cross-check: it must equal the superblock dev,
/// except on btrfs where <c>st_dev</c> is the subvolume's anonymous device by design; there the key adds
/// the subvolume id (ABI 2) once the kernel side is self-checked. Overlayfs
/// (container roots) and any other unexplained mismatch return no key — the rule is then left to
/// nftables and reported uncovered instead of claiming a connect-time verdict that cannot match.
/// </summary>
public static class BpfExeKey
{
    private static readonly HashSet<string> OverlayTypes = new(StringComparer.Ordinal) { "overlay", "fuse.fuse-overlayfs", "aufs" };

    public static BpfExeKeyResolution Resolve(string realPath, BpfInode stat, MountInfoTable mounts, BpfKernelKeyCheck? kernel = null, Func<string, BpfSubvolumeId?>? subvolume = null)
    {
        ArgumentNullException.ThrowIfNull(realPath);
        ArgumentNullException.ThrowIfNull(stat);
        ArgumentNullException.ThrowIfNull(mounts);
        var statDev = string.Create(CultureInfo.InvariantCulture, $"{stat.DevMajor}:{stat.DevMinor}");
        var mount = mounts.Find(realPath);
        if (mount is null)
        {
            return new BpfExeKeyResolution(null, $"no mountinfo entry covers {realPath}; the superblock device the BPF program reads cannot be proven", null);
        }

        var where = $"{mount.FsType} at {mount.MountPoint}{(mount.Root == "/" ? string.Empty : " [root " + mount.Root + "]")}";
        if (OverlayTypes.Contains(mount.FsType))
        {
            return new BpfExeKeyResolution(null, $"{realPath} is on {where}: exe_file->f_inode is the overlay inode, whose device/inode stat does not report reliably", mount);
        }

        if (!string.Equals(mount.FsType, "btrfs", StringComparison.Ordinal))
        {
            if (stat.DevMajor == mount.DevMajor && stat.DevMinor == mount.DevMinor)
            {
                return new BpfExeKeyResolution(new BpfInode(mount.DevMajor, mount.DevMinor, stat.Ino), $"dev {mount.Dev} from mountinfo ({where}; stat agrees), subvol 0 (not btrfs)", mount);
            }

            return new BpfExeKeyResolution(null, $"stat dev {statDev} of {realPath} does not match the superblock dev {mount.Dev} of {where}; the connect-time key cannot be proven", mount);
        }

        // btrfs (PR #276 round 3, item 5, proven on Fedora 45): inode numbers are unique only within a
        // subvolume and every subvolume shares the superblock s_dev, so {s_dev, ino} alone would also match
        // inode N of any other subvolume. ABI 2 adds the subvolume id on both sides; it is used only when
        // the loaded program reads it (self-check passed, CO-RE relocated) and user space can read it too.
        var ambiguous = string.Create(CultureInfo.InvariantCulture, $"exe key ambiguous on btrfs subvolumes: dev {mount.Dev} ino {stat.Ino} (superblock dev from mountinfo; {where}; stat {statDev} is the subvolume device) would also match inode {stat.Ino} of any other subvolume on this filesystem");
        if (kernel is not { State: BpfKernelKeyState.Verified, BtrfsSubvolume: true })
        {
            return new BpfExeKeyResolution(null, $"{ambiguous}, and the loaded BPF program's btrfs subvolume id is not confirmed ({kernel?.Detail ?? "kernel exe key not self-checked"}), so the connect-time exe verdict is not used", mount);
        }

        if (subvolume?.Invoke(realPath) is not { } subvol)
        {
            return new BpfExeKeyResolution(null, $"btrfs subvolume id of {realPath} could not be read (statx STATX_SUBVOL / BTRFS_IOC_INO_LOOKUP); {ambiguous}", mount);
        }

        return new BpfExeKeyResolution(
            new BpfInode(mount.DevMajor, mount.DevMinor, stat.Ino, subvol.Id),
            string.Create(CultureInfo.InvariantCulture, $"dev {mount.Dev} from mountinfo ({where}; stat {statDev} is the subvolume device), subvol {subvol.Id} from {subvol.Source}"),
            mount);
    }
}
/// <summary>Distribution-aware install hint for bpftool, from <c>/etc/os-release</c> ID / ID_LIKE.</summary>
public static class BpftoolHint
{
    public const string Generic = "install bpftool with the distribution's package manager";

    public static string For(string? osRelease)
    {
        var ids = new List<string>();
        foreach (var raw in (osRelease ?? string.Empty).Split('\n'))
        {
            var line = raw.Trim();
            var eq = line.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0)
            {
                continue;
            }

            var name = line[..eq];
            if (name is "ID" or "ID_LIKE")
            {
                ids.AddRange(line[(eq + 1)..].Trim().Trim('"', '\'').ToLowerInvariant().Split(' ', StringSplitOptions.RemoveEmptyEntries));
            }
        }

        if (ids.Contains("ubuntu"))
        {
            return "apt install linux-tools-common linux-tools-$(uname -r)";
        }

        if (ids.Any(id => id is "fedora" or "rhel" or "centos"))
        {
            return "dnf install bpftool";
        }

        if (ids.Any(id => id == "suse" || id.StartsWith("opensuse", StringComparison.Ordinal) || id == "sles"))
        {
            return "zypper install bpftool";
        }

        if (ids.Contains("debian"))
        {
            return "apt install bpftool";
        }

        return Generic;
    }

    /// <summary>Hint for the running system (<c>/etc/os-release</c>, falling back to <c>/usr/lib/os-release</c>).</summary>
    public static string Current()
    {
        foreach (var path in new[] { "/etc/os-release", "/usr/lib/os-release" })
        {
            try
            {
                if (File.Exists(path))
                {
                    return For(File.ReadAllText(path));
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return Generic;
    }
}
