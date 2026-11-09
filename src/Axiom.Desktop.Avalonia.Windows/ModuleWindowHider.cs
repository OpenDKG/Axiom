// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;

namespace Axiom.Desktop.Avalonia.Windows;

/// <summary>
/// Hides console windows that belong to Axiom-managed optional modules (the local DKG node and
/// Blackbox dashboard). Those processes can be started by third-party login tasks rather than by
/// Axiom, so the descendant-only hider is not enough. Matching is by command line; an unrelated
/// user Node.js window is never touched.
/// </summary>
internal sealed class ModuleWindowHider : IDisposable
{
    private const int SwHide = 0;

    private readonly CancellationTokenSource _cancellation = new();

    private Task? _loop;

    public void Start()
    {
        _loop ??= Task.Run(RunAsync);
    }

    public void Dispose()
    {
        _cancellation.Cancel();
        _cancellation.Dispose();
    }

    private async Task RunAsync()
    {
        // The login tasks and their child workers appear over the first minutes. Check often at
        // startup and rarely afterwards; a hidden console is cosmetic and never a dependency.
        var deadline = DateTimeOffset.UtcNow.AddMinutes(3);
        while (!_cancellation.IsCancellationRequested)
        {
            HideModuleWindows();
            var delay = DateTimeOffset.UtcNow < deadline
                ? TimeSpan.FromSeconds(2)
                : TimeSpan.FromSeconds(30);
            try
            {
                await Task.Delay(delay, _cancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private static void HideModuleWindows()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, CommandLine FROM Win32_Process " +
                "WHERE Name = 'node.exe' OR Name = 'python.exe' OR Name = 'hermes.exe'");
            using var results = searcher.Get();
            foreach (ManagementObject item in results)
            {
                var commandLine = item["CommandLine"] as string ?? string.Empty;
                if (!IsAxiomModule(commandLine))
                {
                    continue;
                }

                var processId = Convert.ToInt32(item["ProcessId"], System.Globalization.CultureInfo.InvariantCulture);
                HideProcessWindow(processId);
            }
        }
        catch (Exception exception) when (exception is
                     ManagementException or UnauthorizedAccessException or InvalidOperationException or
                     System.Runtime.InteropServices.COMException or FormatException or OverflowException)
        {
            // Best effort; a missing WMI query must never affect protection or the UI.
        }
    }

    internal static bool IsAxiomModule(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return false;
        }

        if (commandLine.Contains(@"\Axiom\modules\dkg\", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains(@"\Axiom\modules\blackbox\", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains(@"\Axiom\modules\dkg/", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains(@"\Axiom\modules\blackbox/", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Blackbox's official installer keeps its own DKG/Hermes copy under %LOCALAPPDATA%\hermes.
        return commandLine.Contains(@"\hermes\blackbox\", StringComparison.OrdinalIgnoreCase) &&
               (commandLine.Contains("dkg", StringComparison.OrdinalIgnoreCase) ||
                commandLine.Contains("dashboard", StringComparison.OrdinalIgnoreCase) ||
                commandLine.Contains("blackbox", StringComparison.OrdinalIgnoreCase));
    }

    private static void HideProcessWindow(int processId)
    {
        if (processId <= 4)
        {
            return;
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            var handle = process.MainWindowHandle;
            if (handle != IntPtr.Zero && IsWindowVisible(handle))
            {
                _ = ShowWindow(handle, SwHide);
            }
        }
        catch (Exception exception) when (exception is
                     ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
        }
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr window, int command);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr window);
}
