// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Nft;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Bpf;

/// <summary>Inode identity of a file as the kernel sees it: MAJOR/MINOR of the superblock device and the inode number.</summary>
public sealed record BpfInode(uint DevMajor, uint DevMinor, ulong Ino);

/// <summary>Reads inode identities; faked in tests.</summary>
public interface IInodeReader
{
    /// <summary>Identity of the file behind <paramref name="path"/> (symlinks followed), or null when it does not exist.</summary>
    BpfInode? Stat(string path);

    /// <summary>cgroup v2 id of a cgroup-relative path (its directory inode number), or null when absent.</summary>
    ulong? CgroupId(string cgroupPath);

    /// <summary>Canonical path (every symlink resolved), or null when it cannot be resolved.</summary>
    string? RealPath(string path);

    /// <summary>Text of the daemon's <c>/proc/self/mountinfo</c>, or null when unreadable.</summary>
    string? ReadMountInfo();
}

/// <summary>GNU coreutils <c>stat</c> backed reader: <c>stat -L -c '%Hd %Ld %i'</c> (major, minor, inode).</summary>
public sealed class StatInodeReader : IInodeReader
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private readonly IProcessRunner _runner;
    private readonly string _cgroupRoot;

    public StatInodeReader(IProcessRunner runner, string? cgroupRoot = null)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _cgroupRoot = string.IsNullOrWhiteSpace(cgroupRoot) ? BpfEnginePaths.DefaultCgroupRoot : cgroupRoot;
    }

    public BpfInode? Stat(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var result = _runner.Run("stat", ["-L", "-c", "%Hd %Ld %i", path], Timeout);
        return result.Succeeded ? Parse(result.StandardOutput) : null;
    }

    public ulong? CgroupId(string cgroupPath)
    {
        ArgumentNullException.ThrowIfNull(cgroupPath);
        var absolute = Path.Combine(_cgroupRoot, cgroupPath.TrimStart('/'));
        var result = _runner.Run("stat", ["-c", "%i", absolute], Timeout);
        return result.Succeeded && ulong.TryParse(result.StandardOutput.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var id) ? id : null;
    }

    public string? RealPath(string path) => path;

    public string? ReadMountInfo() => null;

    /// <summary>Parses "major minor inode" (pure; unit-tested).</summary>
    public static BpfInode? Parse(string statOutput)
    {
        ArgumentNullException.ThrowIfNull(statOutput);
        var parts = statOutput.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 3 &&
               uint.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var major) &&
               uint.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var minor) &&
               ulong.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var ino)
            ? new BpfInode(major, minor, ino)
            : null;
    }
}

/// <summary>One desired map entry (key and value already encoded).</summary>
public sealed record BpfMapEntry(string Map, byte[] Key, byte[] Value, string Describe)
{
    public string KeyHex => BpfLayout.HexString(Key);
}

/// <summary>A rule the BPF layer cannot express; nftables still enforces it (with the race window).</summary>
public sealed record BpfUncoveredRule(Guid RuleId, string Reason);

public sealed record BpfVerdictPlan(IReadOnlyList<BpfMapEntry> Entries, IReadOnlyList<BpfUncoveredRule> Uncovered)
{
    public int ExeEntries => Entries.Count(entry => entry.Map == BpfLayout.ExeMap);

    public int CgroupEntries => Entries.Count(entry => entry.Map == BpfLayout.CgroupMap);
}

/// <summary>
/// Turns the enabled rules of a generation into verdict-map entries (docs/LINUX_EBPF.md §3).
/// Only <b>outbound block rules without address or port scope</b> become entries: the program
/// decides at connect() from the exe inode and the cgroup id alone, and widening a scoped rule
/// into "block everything" is never acceptable. Scoped block rules and allow rules are reported
/// as <see cref="BpfUncoveredRule"/> (nft enforces them; the race window stays for those). Several
/// block rules of the same app merge their protocol masks under the first rule's id.
/// </summary>
public static class BpfVerdictPlanner
{
    public static BpfVerdictPlan Plan(IEnumerable<RuleSpec> specs, long generation, IAppCgroupResolver cgroups, IInodeReader inodes)
    {
        ArgumentNullException.ThrowIfNull(specs);
        ArgumentNullException.ThrowIfNull(cgroups);
        ArgumentNullException.ThrowIfNull(inodes);

        var uncovered = new List<BpfUncoveredRule>();
        var byApp = new Dictionary<string, (Guid RuleId, byte ProtoMask)>(StringComparer.Ordinal);
        foreach (var spec in specs.Where(spec => spec.Enabled))
        {
            if (!TryCover(spec, out var protoMask, out var reason))
            {
                uncovered.Add(new BpfUncoveredRule(spec.ManagedRuleId, reason));
                continue;
            }

            var app = spec.AppPath.Trim();
            byApp[app] = byApp.TryGetValue(app, out var existing)
                ? (existing.RuleId, (byte)(existing.ProtoMask | protoMask))
                : (spec.ManagedRuleId, protoMask);
        }

        var entries = new List<BpfMapEntry>();
        foreach (var (app, (ruleId, protoMask)) in byApp.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            var value = BpfLayout.Verdict(BpfLayout.ActionBlock, protoMask, generation, ruleId);
            var inode = inodes.Stat(app);
            if (inode is null)
            {
                uncovered.Add(new BpfUncoveredRule(ruleId, $"appPath is not reachable on this system: {app}"));
            }
            else if (Directory.Exists(app))
            {
                // A directory rule matches by path prefix; one inode cannot express it. The cgroup key still applies.
                uncovered.Add(new BpfUncoveredRule(ruleId, $"appPath is a directory; only its herded cgroup is keyed at connect time: {app}"));
            }
            else
            {
                entries.Add(new BpfMapEntry(
                    BpfLayout.ExeMap,
                    BpfLayout.ExeKey(inode.DevMajor, inode.DevMinor, inode.Ino),
                    value,
                    string.Create(CultureInfo.InvariantCulture, $"exe {app} dev {inode.DevMajor}:{inode.DevMinor} ino {inode.Ino} proto 0x{protoMask:x}")));
            }

            if (cgroups.TryResolve(app, out var cgroupPath, out _) && inodes.CgroupId(cgroupPath) is { } cgroupId)
            {
                entries.Add(new BpfMapEntry(
                    BpfLayout.CgroupMap,
                    BpfLayout.CgroupKey(cgroupId),
                    value,
                    string.Create(CultureInfo.InvariantCulture, $"cgroup {cgroupPath} id {cgroupId} proto 0x{protoMask:x}")));
            }
        }

        return new BpfVerdictPlan(entries, uncovered);
    }

    /// <summary>Whether a rule can be expressed as an exe/cgroup verdict; the protocol mask when it can.</summary>
    public static bool TryCover(RuleSpec spec, out byte protoMask, out string reason)
    {
        ArgumentNullException.ThrowIfNull(spec);
        protoMask = 0;
        reason = string.Empty;
        if (spec.Action != FirewallAction.Block)
        {
            reason = "allow rules are not keyed at connect time (nothing to block)";
            return false;
        }

        if (spec.Direction != FirewallDirection.Outbound)
        {
            reason = "inbound rules have no connect() hook; nftables enforces them";
            return false;
        }

        var addresses = (spec.RemoteAddresses ?? []).Select(address => address.Trim()).Where(address => address.Length > 0).ToList();
        if (addresses.Count > 0 && addresses.Any(address => address is not ("*" or "0.0.0.0/0" or "::/0")))
        {
            reason = "remote address scope is enforced by nftables only (connect-time verdict covers unscoped block rules)";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(spec.RemotePorts) && spec.RemotePorts.Trim() != "*")
        {
            reason = "remote port scope is enforced by nftables only (connect-time verdict covers unscoped block rules)";
            return false;
        }

        if (string.IsNullOrWhiteSpace(spec.AppPath) || !spec.AppPath.Trim().StartsWith('/'))
        {
            reason = "appPath must be absolute";
            return false;
        }

        protoMask = spec.Protocol switch
        {
            NetworkProtocol.Tcp => BpfLayout.ProtoTcp,
            NetworkProtocol.Udp => BpfLayout.ProtoUdp,
            _ => BpfLayout.ProtoAny,
        };
        return true;
    }
}
