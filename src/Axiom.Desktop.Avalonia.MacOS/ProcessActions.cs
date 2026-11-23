// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.MacOS;

/// <summary>Ends processes only after verifying identity and confirmation.</summary>
public sealed class ProcessActions : IProcessActions
{
    public int EndProcesses(IReadOnlyList<int> processIds)
    {
        ArgumentNullException.ThrowIfNull(processIds);
        return EndProcesses(processIds.Select(pid => new ProcessTerminationTarget(pid)).ToArray());
    }

    public int EndProcesses(IReadOnlyList<ProcessTerminationTarget> targets)
    {
        ArgumentNullException.ThrowIfNull(targets);

        var ended = 0;
        foreach (var target in targets)
        {
            if (target.ProcessId <= 0)
            {
                continue;
            }

            try
            {
                using var process = Process.GetProcessById(target.ProcessId);
                if (!ProcessTerminationTarget.MatchesLiveProcess(process, target))
                {
                    continue;
                }

                process.Kill(entireProcessTree: false);
                ended++;
            }
#pragma warning disable CA1031 // A protected or already-exited process must not crash the UI.
            catch (Exception)
#pragma warning restore CA1031
            {
            }
        }

        return ended;
    }
}
