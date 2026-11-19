// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.MacOS;

/// <summary>Ends a process tree only after the page asked the operator to confirm.</summary>
public sealed class ProcessActions : IProcessActions
{
    public int EndProcesses(IReadOnlyList<int> processIds)
    {
        ArgumentNullException.ThrowIfNull(processIds);

        var ended = 0;
        foreach (var pid in processIds)
        {
            try
            {
                using var process = Process.GetProcessById(pid);
                process.Kill(entireProcessTree: true);
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
