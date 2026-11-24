// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;

namespace Axiom.Setup;

/// <summary>
/// Closes running Axiom desktop instances before an update or uninstall. When Setup is launched
/// from the running desktop app's in-app updater, Setup is a child process of <c>Axiom.Desktop</c>
/// and <see cref="Process.Kill(bool)"/> with <c>entireProcessTree: true</c> throws
/// <see cref="InvalidOperationException"/> because the tree contains Setup itself; in that case
/// this helper falls back to terminating only the desktop process.
/// </summary>
internal static class SetupProcessCloser
{
    internal static readonly string[] DesktopProcessNames = ["Axiom.Desktop", "Netpetra.Desktop"];

    internal static void TerminateProcess(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        if (process.HasExited)
        {
            return;
        }

        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
            // Setup is a descendant of the target (launched by the in-app updater): terminate only
            // the target desktop process instead of the subtree containing Setup itself.
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: false);
            }
        }

        _ = process.WaitForExit(5000);
    }

    internal static bool CloseDesktopProcesses(Action<string>? report, int gracefulWaitMs = 2500)
    {
        var running = DesktopProcessNames
            .SelectMany(Process.GetProcessesByName)
            .ToArray();
        if (running.Length == 0)
        {
            return true;
        }

        report?.Invoke($"Closing {running.Length} running Axiom desktop process(es)...");
        try
        {
            foreach (var proc in running)
            {
                try
                {
                    if (proc.Id == Environment.ProcessId || proc.HasExited)
                    {
                        continue;
                    }

                    // CloseMainWindow typically minimizes/hides to the tray when tray notifications
                    // are enabled; wait briefly, then terminate the desktop process explicitly.
                    _ = proc.CloseMainWindow();
                    if (!proc.WaitForExit(gracefulWaitMs))
                    {
                        TerminateProcess(proc);
                    }
                }
                catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
                {
                }
            }

            for (var attempt = 0; attempt < 20; attempt++)
            {
                if (!AnyRunning())
                {
                    return true;
                }

                Thread.Sleep(250);
            }

            report?.Invoke("Axiom could not be closed automatically. Exit Axiom from its tray icon and run Setup again.");
            return false;
        }
        finally
        {
            foreach (var proc in running)
            {
                proc.Dispose();
            }
        }
    }

    private static bool AnyRunning()
    {
        foreach (var name in DesktopProcessNames)
        {
            var processes = Process.GetProcessesByName(name);
            var any = processes.Any(proc => proc.Id != Environment.ProcessId);
            foreach (var process in processes)
            {
                process.Dispose();
            }

            if (any)
            {
                return true;
            }
        }

        return false;
    }
}
