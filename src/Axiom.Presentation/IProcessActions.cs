// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;

namespace Axiom.Presentation;

/// <summary>
/// Snapshot identity for a process captured before asking the operator to confirm termination,
/// preventing stale-PID kills if the OS reuses a PID while the dialog is open.
/// </summary>
public sealed record ProcessTerminationTarget(
    int ProcessId,
    DateTimeOffset? StartTimeUtc = null,
    string? ExpectedPath = null)
{
    public static IReadOnlyList<ProcessTerminationTarget> Capture(
        IEnumerable<int> processIds,
        string? expectedPath = null)
    {
        var list = new List<ProcessTerminationTarget>();
        foreach (var pid in processIds.Where(id => id > 0).Distinct())
        {
            DateTimeOffset? startUtc = null;
            string? resolvedPath = string.IsNullOrWhiteSpace(expectedPath) || expectedPath == "—"
                ? null
                : expectedPath;
            try
            {
                using var process = Process.GetProcessById(pid);
                startUtc = process.StartTime.ToUniversalTime();
                resolvedPath ??= process.MainModule?.FileName;
            }
            catch (Exception exception) when (exception is
                         ArgumentException or InvalidOperationException or
                         System.ComponentModel.Win32Exception or NotSupportedException)
            {
            }

            list.Add(new ProcessTerminationTarget(pid, startUtc, resolvedPath));
        }

        return list;
    }

    public static bool MatchesLiveProcess(Process process, ProcessTerminationTarget target)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(target);

        if (target.StartTimeUtc is { } expectedStart)
        {
            var actualStart = process.StartTime.ToUniversalTime();
            if (Math.Abs((actualStart - expectedStart).TotalSeconds) > 2.0)
            {
                return false;
            }
        }

        if (!string.IsNullOrWhiteSpace(target.ExpectedPath))
        {
            string? actualPath = null;
            try
            {
                actualPath = process.MainModule?.FileName;
            }
            catch (Exception exception) when (exception is
                         System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
            {
            }

            if (!string.IsNullOrWhiteSpace(actualPath))
            {
                var comparison = OperatingSystem.IsWindows()
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal;
                if (!string.Equals(Path.GetFullPath(actualPath), Path.GetFullPath(target.ExpectedPath), comparison))
                {
                    return false;
                }
            }
        }

        return true;
    }
}

/// <summary>
/// Host process control. Axiom only calls this after an explicit confirmation on the Applications
/// page; it never runs for an automatic or background action.
/// </summary>
public interface IProcessActions
{
    /// <summary>Ends each accessible process. Returns how many were ended.</summary>
    int EndProcesses(IReadOnlyList<int> processIds);

    /// <summary>
    /// Ends each process only if its PID still matches the captured start time / executable path.
    /// </summary>
    int EndProcesses(IReadOnlyList<ProcessTerminationTarget> targets) =>
        EndProcesses(targets.Select(target => target.ProcessId).ToArray());
}
