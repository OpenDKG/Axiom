// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Axiom.Infrastructure.Linux.Bpf;

/// <summary>
/// User-space side of the ABI 2 exe key (docs/LINUX_EBPF.md §2.1): the btrfs subvolume id (root
/// objectid) of a file, the number the BPF program reads as <c>BTRFS_I(inode)->root->root_key.objectid</c>.
/// Preferred source is <c>statx(STATX_SUBVOL)</c> (<c>stx_subvol</c>, Linux 6.10+); the fallback is
/// <c>BTRFS_IOC_INO_LOOKUP</c> with treeid 0 / objectid 256 (BTRFS_FIRST_FREE_OBJECTID), which the kernel
/// answers with the fd's subvolume id without CAP_SYS_ADMIN. When both answer they must agree.
/// </summary>
public static class BtrfsSubvolumeReader
{
    private const int AtFdCwd = -100;
    private const uint StatxIno = 0x100;
    private const uint StatxSubvol = 0x8000;
    private const int StatxSize = 256;
    private const int StatxSubvolOffset = 160;
    private const int InoLookupSize = 4096;
    private const ulong FirstFreeObjectId = 256;

    /// <summary>_IOWR(0x94, 18, struct btrfs_ioctl_ino_lookup_args) = 0xD0009412.</summary>
    private const uint BtrfsIocInoLookup = 0xD0009412;

    /// <summary>Reads both sources for <paramref name="path"/> (symlinks followed) and combines them.</summary>
    public static BpfSubvolumeId? Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return OperatingSystem.IsLinux() ? Combine(FromStatx(path), FromIoctl(path)) : null;
    }

    /// <summary>statx first; the ioctl alone when statx has no STATX_SUBVOL; null when they disagree or neither answers.</summary>
    public static BpfSubvolumeId? Combine(ulong? statx, ulong? ioctl) => (statx, ioctl) switch
    {
        ({ } s, { } i) when s == i => new BpfSubvolumeId(s, "statx STATX_SUBVOL (BTRFS_IOC_INO_LOOKUP agrees)"),
        ({ }, { }) => null,
        ({ } s, null) => new BpfSubvolumeId(s, "statx STATX_SUBVOL"),
        (null, { } i) => new BpfSubvolumeId(i, "BTRFS_IOC_INO_LOOKUP"),
        _ => null,
    };

    /// <summary>stx_subvol when the kernel filled STATX_SUBVOL, else null.</summary>
    public static ulong? FromStatx(string path)
    {
        var buffer = new byte[StatxSize];
        try
        {
            if (statx(AtFdCwd, path, 0, StatxIno | StatxSubvol, buffer) != 0)
            {
                return null;
            }
        }
        catch (Exception exception) when (exception is EntryPointNotFoundException or DllNotFoundException)
        {
            return null;
        }

        var mask = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(0, 4));
        return (mask & StatxSubvol) != 0 ? BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(StatxSubvolOffset, 8)) : null;
    }

    /// <summary>The treeid BTRFS_IOC_INO_LOOKUP returns for the file's own subvolume, else null (not btrfs: ENOTTY).</summary>
    public static ulong? FromIoctl(string path)
    {
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var args = new byte[InoLookupSize];
            BinaryPrimitives.WriteUInt64LittleEndian(args.AsSpan(8, 8), FirstFreeObjectId);
            var added = false;
            handle.DangerousAddRef(ref added);
            try
            {
                if (ioctl((int)handle.DangerousGetHandle(), BtrfsIocInoLookup, args) != 0)
                {
                    return null;
                }
            }
            finally
            {
                if (added)
                {
                    handle.DangerousRelease();
                }
            }

            var treeId = BinaryPrimitives.ReadUInt64LittleEndian(args.AsSpan(0, 8));
            return treeId == 0 ? null : treeId;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or EntryPointNotFoundException or DllNotFoundException)
        {
            return null;
        }
    }

    [DllImport("libc", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    private static extern int statx(int dirfd, [MarshalAs(UnmanagedType.LPUTF8Str)] string pathname, int flags, uint mask, byte[] statxbuf);

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, nuint request, byte[] argp);
}
