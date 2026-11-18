// SPDX-License-Identifier: GPL-3.0-or-later
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
        var cancellationToken = _cancellation.Token;
        _loop ??= Task.Run(() => RunAsync(cancellationToken));
    }

    public void Dispose()
    {
        _cancellation.Cancel();
        _cancellation.Dispose();
    }

    private static async Task RunAsync(CancellationToken cancellationToken)
    {
        // Vendor login tasks may start alongside Axiom. Later Axiom launches use the bounded
        // descendant hider and do not need a recurring WMI scan.
        var deadline = DateTimeOffset.UtcNow.AddMinutes(3);
        while (!cancellationToken.IsCancellationRequested && DateTimeOffset.UtcNow < deadline)
        {
            if (!Axiom.Presentation.BackgroundWindowSettingsStore.Enabled)
            {
                return;
            }

            HideModuleWindows();
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
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
                "WHERE Name = 'node.exe' OR Name = 'python.exe' OR Name = 'pythonw.exe' " +
                "OR Name = 'hermes.exe' OR Name = 'cmd.exe' OR Name = 'powershell.exe' OR Name = 'pwsh.exe'");
            using var results = searcher.Get();
            var modulePids = new HashSet<uint>();
            foreach (ManagementObject item in results)
            {
                using (item)
                {
                    if (item["ProcessId"] is uint processId && processId > 4 &&
                        IsAxiomModule(item["CommandLine"] as string ?? string.Empty))
                    {
                        modulePids.Add(processId);
                    }
                }
            }

            if (modulePids.Count > 0)
            {
                _ = EnumWindows((window, parameter) =>
                {
                    _ = GetWindowThreadProcessId(window, out var ownerPid);
                    if (modulePids.Contains(ownerPid) && IsWindowVisible(window))
                    {
                        _ = ShowWindow(window, SwHide);
                    }

                    return true;
                }, IntPtr.Zero);
            }
        }
        catch (Exception exception) when (exception is
                     ManagementException or UnauthorizedAccessException or InvalidOperationException or
                     System.Runtime.InteropServices.COMException or FormatException or OverflowException)
        {
            // Best effort; a missing WMI query must never affect protection or the UI.
        }
    }

    internal static bool IsAxiomModule(string commandLine) =>
        Axiom.Presentation.AxiomModuleProcessMatcher.IsAxiomModuleCommandLine(commandLine);

    private delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr window, int command);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr window);
}
