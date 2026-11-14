// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.Linux.Bpf;

public enum BpfKernelKeyState
{
    Unverified,
    Verified,
    Mismatch,
}

/// <summary>What the loaded program recorded for the daemon's own exe (axiom_selfcheck).</summary>
public sealed record BpfSelfCheckRecord(uint TargetTgid, uint Hits, BpfInode Key, uint Flags)
{
    public bool BtrfsCoRe => (Flags & 1u) != 0;

    public bool ExeOnBtrfs => (Flags & 2u) != 0;
}

public sealed record BpfKernelKeyCheck(BpfKernelKeyState State, bool BtrfsSubvolume, string Detail)
{
    public static BpfKernelKeyCheck Unverified(string detail) => new(BpfKernelKeyState.Unverified, false, detail);

    public static BpfKernelKeyCheck Compare(BpfSelfCheckRecord? record, int pid, string exePath, Func<bool, BpfExeKeyResolution> userspace) => Unverified("stub");
}
