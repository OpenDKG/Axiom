// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.Linux;

/// <summary>Why a pid was not signalled. Pure decision, unit-tested.</summary>
public enum ProcessActionRefusal
{
    None,
    InvalidPid,
    InitProcess,
    OwnProcess,
    RootOwned,
    ForeignUser,
    NotFound,
}

/// <summary>
/// Ends a process only after the page asked the operator to confirm: SIGTERM first, then SIGKILL
/// for whatever is still alive after <see cref="Grace"/>. The desktop runs unprivileged, so the
/// kernel refuses foreign pids anyway; the checks here make the refusal explicit and keep pid 1,
/// this process and root-owned processes off the list even when Axiom itself runs as root.
/// </summary>
public sealed class ProcessActions : IProcessActions
{
    public static readonly TimeSpan Grace = TimeSpan.FromSeconds(2);

    private const int SigTerm = 15;
    private const int SigKill = 9;

    private readonly Func<int, uint?> _ownerUid;
    private readonly int _ownPid;
    private readonly uint _ownUid;
    private readonly Func<int, int, bool> _signal;
    private readonly Func<int, bool> _isAlive;
    private readonly TimeSpan _grace;

    public ProcessActions()
        : this(ReadOwnerUid, Environment.ProcessId, GetEuid(), SendSignal, IsAlive, Grace)
    {
    }

    internal ProcessActions(
        Func<int, uint?> ownerUid,
        int ownPid,
        uint ownUid,
        Func<int, int, bool> signal,
        Func<int, bool> isAlive,
        TimeSpan grace)
    {
        _ownerUid = ownerUid;
        _ownPid = ownPid;
        _ownUid = ownUid;
        _signal = signal;
        _isAlive = isAlive;
        _grace = grace;
    }

    /// <summary>Pure policy: which pids may be signalled by a process with <paramref name="ownUid"/>.</summary>
    public static ProcessActionRefusal Decide(int pid, int ownPid, uint ownUid, uint? targetUid)
    {
        if (pid <= 0)
        {
            return ProcessActionRefusal.InvalidPid;
        }

        if (pid == 1)
        {
            return ProcessActionRefusal.InitProcess;
        }

        if (pid == ownPid)
        {
            return ProcessActionRefusal.OwnProcess;
        }

        if (targetUid is null)
        {
            return ProcessActionRefusal.NotFound;
        }

        if (ownUid != 0 && targetUid == 0)
        {
            return ProcessActionRefusal.RootOwned;
        }

        if (ownUid != 0 && targetUid != ownUid)
        {
            return ProcessActionRefusal.ForeignUser;
        }

        return ProcessActionRefusal.None;
    }

    public int EndProcesses(IReadOnlyList<int> processIds)
    {
        ArgumentNullException.ThrowIfNull(processIds);

        var signalled = new List<int>();
        foreach (var pid in processIds)
        {
            var refusal = Decide(pid, _ownPid, _ownUid, _ownerUid(pid));
            if (refusal != ProcessActionRefusal.None)
            {
                StartupLog.Write("process", $"pid {pid} not ended: {refusal}");
                continue;
            }

            if (_signal(pid, SigTerm))
            {
                signalled.Add(pid);
            }
        }

        if (signalled.Count == 0)
        {
            return 0;
        }

        var deadline = DateTime.UtcNow + _grace;
        while (DateTime.UtcNow < deadline && signalled.Any(_isAlive))
        {
            Thread.Sleep(100);
        }

        foreach (var pid in signalled.Where(_isAlive))
        {
            _signal(pid, SigKill);
        }

        return signalled.Count;
    }

    /// <summary>Owner of a pid from <c>/proc/&lt;pid&gt;/status</c> (real uid), or null when gone.</summary>
    internal static uint? ReadOwnerUid(int pid)
    {
        try
        {
            foreach (var line in File.ReadLines($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/status"))
            {
                if (line.StartsWith("Uid:", StringComparison.Ordinal))
                {
                    return ParseUidLine(line);
                }
            }

            return null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary><c>Uid:\t1000\t1000\t1000\t1000</c> → 1000 (the real uid).</summary>
    internal static uint? ParseUidLine(string line)
    {
        var parts = line.Split((char[])['\t', ' '], StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 && uint.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var uid) ? uid : null;
    }

    private static bool IsAlive(int pid) => Directory.Exists($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}");

    private static bool SendSignal(int pid, int signal) => NativeMethods.kill(pid, signal) == 0;

    private static uint GetEuid() => NativeMethods.geteuid();

    private static class NativeMethods
    {
        [DllImport("libc", SetLastError = true)]
        internal static extern int kill(int pid, int sig);

        [DllImport("libc")]
        internal static extern uint geteuid();
    }
}
