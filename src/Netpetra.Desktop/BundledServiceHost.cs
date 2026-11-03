// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;

namespace Netpetra.Desktop;

/// <summary>
/// Starts the bundled service next to the desktop executable so a release extraction works without
/// a separate terminal. It reuses an already running service and stops only a process it started.
/// </summary>
internal sealed class BundledServiceHost : IDisposable
{
    private Process? _owned;

    public bool TryStart()
    {
        var servicePath = Path.Combine(AppContext.BaseDirectory, "Netpetra.Service.exe");
        if (!File.Exists(servicePath))
        {
            return false;
        }

        if (Process.GetProcessesByName("Netpetra.Service").Length > 0)
        {
            return true;
        }

        try
        {
            _owned = Process.Start(new ProcessStartInfo(servicePath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
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
