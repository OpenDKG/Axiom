// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace Axiom.Desktop.Avalonia.Windows;

/// <summary>
/// Starts the bundled service next to the desktop executable so a release extraction works without
/// a separate terminal. It reuses an already running service and stops only a process it started.
/// This mirrors the WPF host behaviour until the installer cutover.
/// </summary>
internal sealed class BundledServiceHost : IDisposable
{
    private Process? _owned;

    public bool TryStart()
    {
        var servicePath = Path.Combine(AppContext.BaseDirectory, "Axiom.Service.exe");
        if (!File.Exists(servicePath))
        {
            return false;
        }

        HideExistingServiceWindows();

        // An installed Windows service owns the pipe. Starting a second, interactive copy next to
        // it would create two pipe servers and two history writers, so never spawn in that case.
        if (IsServiceRegistered())
        {
            return true;
        }

        if (Process.GetProcessesByName("Axiom.Service").Length > 0)
        {
            return true;
        }

        try
        {
            _owned = Process.Start(new ProcessStartInfo(servicePath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = AppContext.BaseDirectory,
            });

            return _owned is not null;
        }
#pragma warning disable CA1031 // A missing service must fall back to in-process monitoring.
        catch (Exception)
#pragma warning restore CA1031
        {
            return false;
        }
    }

    private static bool IsServiceRegistered()
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "sc.exe"),
                Arguments = "query Axiom",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });

            if (process is null)
            {
                return false;
            }

            process.WaitForExit(5000);
            return process.ExitCode == 0;
        }
#pragma warning disable CA1031 // Detection is best-effort; a failure means "not installed".
        catch (Exception)
#pragma warning restore CA1031
        {
            return false;
        }
    }

    private static void HideExistingServiceWindows()
    {
        foreach (var process in Process.GetProcessesByName("Axiom.Service"))
        {
            try
            {
                var handle = process.MainWindowHandle;
                if (handle != IntPtr.Zero)
                {
                    _ = NativeWindowMethods.ShowWindow(handle, 0);
                }
            }
            catch (Exception exception) when (exception is
                         InvalidOperationException or System.ComponentModel.Win32Exception)
            {
            }
            finally
            {
                process.Dispose();
            }
        }
    }

    public void Dispose()
    {
        if (_owned is not { HasExited: false })
        {
            _owned?.Dispose();
            return;
        }

        try
        {
            _owned.Kill(entireProcessTree: true);
            _owned.WaitForExit(2000);
        }
#pragma warning disable CA1031 // Best-effort shutdown; the OS reclaims the process.
        catch (Exception)
#pragma warning restore CA1031
        {
        }
        finally
        {
            _owned.Dispose();
        }
    }
}

internal static class NativeWindowMethods
{
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ShowWindow(IntPtr window, int command);
}
