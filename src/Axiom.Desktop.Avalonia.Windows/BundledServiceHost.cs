// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

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

        // An installed Windows service owns the pipe. Starting a second, interactive copy next to
        // it would create two pipe servers and two history writers, so never spawn in that case.
        if (HideExistingServiceWindows() || IsServiceRegistered())
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
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Axiom");
            return key is not null;
        }
#pragma warning disable CA1031 // Detection is best-effort; a failure means "not installed".
        catch (Exception)
#pragma warning restore CA1031
        {
            return false;
        }
    }

    private static bool HideExistingServiceWindows()
    {
        var processes = Process.GetProcessesByName("Axiom.Service");
        foreach (var process in processes)
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

        return processes.Length > 0;
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
