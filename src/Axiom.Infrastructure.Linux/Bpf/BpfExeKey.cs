// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.Linux.Bpf;

/// <summary>One line of <c>/proc/self/mountinfo</c> (proc(5)); RED stub.</summary>
public sealed record MountInfoEntry(int MountId, int ParentId, uint DevMajor, uint DevMinor, string Root, string MountPoint, string FsType, string Source);

/// <summary>RED stub.</summary>
public sealed class MountInfoTable
{
    public IReadOnlyList<MountInfoEntry> Entries { get; } = [];

    public static MountInfoTable Parse(string? text) => throw new NotImplementedException();

    public MountInfoEntry? Find(string absolutePath) => throw new NotImplementedException();

    public static string Unescape(string field) => throw new NotImplementedException();
}

/// <summary>RED stub.</summary>
public sealed record BpfExeKeyResolution(BpfInode? Key, string Detail, MountInfoEntry? Mount);

/// <summary>RED stub.</summary>
public static class BpfExeKey
{
    public static BpfExeKeyResolution Resolve(string realPath, BpfInode stat, MountInfoTable mounts) => throw new NotImplementedException();
}

/// <summary>RED stub.</summary>
public static class BpftoolHint
{
    public static string For(string? osRelease) => throw new NotImplementedException();
}
