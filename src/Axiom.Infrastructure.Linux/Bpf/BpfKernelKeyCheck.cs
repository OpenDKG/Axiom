// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;

namespace Axiom.Infrastructure.Linux.Bpf;

public enum BpfKernelKeyState
{
    /// <summary>No usable record (old object, no connect seen, own key not provable): btrfs exe keys stay nft-only.</summary>
    Unverified,

    /// <summary>The program's key for the daemon's own exe equals the user-space key.</summary>
    Verified,

    /// <summary>The program computed a different key: no exe key can be trusted.</summary>
    Mismatch,
}

/// <summary>What the loaded program recorded for the daemon's own exe (<c>axiom_selfcheck[0]</c>).</summary>
public sealed record BpfSelfCheckRecord(uint TargetTgid, uint Hits, BpfInode Key, uint Flags)
{
    /// <summary>AXIOM_SELFCHECK_BTRFS_CORE: btrfs_inode/btrfs_root were relocated against the kernel's BTF at load.</summary>
    public bool BtrfsCoRe => (Flags & 1u) != 0;

    /// <summary>AXIOM_SELFCHECK_EXE_BTRFS: the recorded exe is on a btrfs superblock.</summary>
    public bool ExeOnBtrfs => (Flags & 2u) != 0;
}

/// <summary>
/// Kernel/user-space exe key self-check (docs/LINUX_EBPF.md §2.1). <see cref="BtrfsSubvolume"/> is true
/// only when the check passed and the program reads the btrfs subvolume id (CO-RE relocated); only then
/// are btrfs exe keys written. <see cref="BpfKernelKeyState.Mismatch"/> drops every exe key.
/// </summary>
public sealed record BpfKernelKeyCheck(BpfKernelKeyState State, bool BtrfsSubvolume, string Detail)
{
    public static BpfKernelKeyCheck Unverified(string detail) => new(BpfKernelKeyState.Unverified, false, detail);

    /// <summary>
    /// Compares the recorded kernel key with the user-space derivation for <paramref name="exePath"/>;
    /// <paramref name="userspace"/> resolves the key assuming the kernel side does (true) or does not
    /// (false) read btrfs subvolume ids.
    /// </summary>
    public static BpfKernelKeyCheck Compare(BpfSelfCheckRecord? record, int pid, string exePath, Func<bool, BpfExeKeyResolution> userspace)
    {
        ArgumentNullException.ThrowIfNull(exePath);
        ArgumentNullException.ThrowIfNull(userspace);
        if (record is null)
        {
            return Unverified("axiom_selfcheck could not be read back (object without the self-check map?)");
        }

        if (record.TargetTgid != unchecked((uint)pid))
        {
            return Unverified(string.Create(CultureInfo.InvariantCulture, $"axiom_selfcheck is armed for tgid {record.TargetTgid}, not pid {pid}"));
        }

        if (record.Hits == 0)
        {
            return Unverified(string.Create(CultureInfo.InvariantCulture, $"the program recorded no connect() of pid {pid} (programs not attached at this cgroup?)"));
        }

        var kernel = Describe(record.Key);
        var resolution = userspace(record.BtrfsCoRe);
        if (resolution.Key is not { } expected)
        {
            return Unverified($"kernel key for {exePath} is {kernel}, but the user-space key is not provable: {resolution.Detail}");
        }

        var core = record.BtrfsCoRe ? "btrfs subvolume read relocated (CO-RE)" : "no btrfs BTF at load: btrfs subvolume ids are not read";
        return expected == record.Key
            ? new BpfKernelKeyCheck(BpfKernelKeyState.Verified, record.BtrfsCoRe, $"kernel and user space agree for {exePath}: {kernel}{(record.ExeOnBtrfs ? " (btrfs)" : string.Empty)}; {core}")
            : new BpfKernelKeyCheck(BpfKernelKeyState.Mismatch, false, $"kernel/userspace exe key mismatch for {exePath}: kernel {kernel}, user space {Describe(expected)} ({resolution.Detail}); no exe key is trusted, exe rules are nft-only plus their cgroup key");
    }

    public static string Describe(BpfInode key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return string.Create(CultureInfo.InvariantCulture, $"dev {key.DevMajor}:{key.DevMinor} ino {key.Ino} subvol {key.Subvolume}");
    }
}
