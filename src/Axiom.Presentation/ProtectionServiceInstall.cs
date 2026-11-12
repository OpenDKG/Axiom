// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;

namespace Axiom.Presentation;

public sealed record ProtectionInstallResult(bool Success, string Message);

/// <summary>
/// One-time elevation: installs and starts the Axiom Windows service through a UAC prompt. The
/// desktop app never runs elevated itself, and the service cannot be removed by this call.
/// </summary>
public static class ProtectionServiceInstall
{
    public static ProtectionInstallResult InstallAndStart()
    {
        if (!OperatingSystem.IsWindows())
        {
            return new ProtectionInstallResult(
                false,
                OperatingSystem.IsMacOS()
                    ? "Use InstallAndStartMacAsync to install the macOS daemon."
                    : OperatingSystem.IsLinux()
                        ? "Use InstallAndStartLinuxAsync to install the Linux daemon."
                        : "Axiom Shield is not available on this platform.");
        }

        var executable = Path.Combine(AppContext.BaseDirectory, "Axiom.Service.exe");
        if (!File.Exists(executable))
        {
            return new ProtectionInstallResult(
                false,
                "Axiom.Service.exe was not found next to the application.");
        }

        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = executable,
                Arguments = "--install-service",
                UseShellExecute = true,
                Verb = "runas",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            });

            if (process is null)
            {
                return new ProtectionInstallResult(false, "The elevated installer did not start.");
            }

            process.WaitForExit(180_000);

            return process.ExitCode == 0
                ? new ProtectionInstallResult(true, "The Axiom service is installed and starting.")
                : new ProtectionInstallResult(
                    false,
                    $"The elevated installer exited with code {process.ExitCode}.");
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            return new ProtectionInstallResult(false, "Administrator approval was cancelled.");
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException)
        {
            return new ProtectionInstallResult(false, $"The service could not be installed: {exception.Message}");
        }
    }

    /// <summary>
    /// macOS: registers the bundled <c>axiomd</c> as the <c>com.axiom.service</c> launchd daemon
    /// (<c>axiomd --install-service</c>) after the standard administrator password dialog. The
    /// desktop app stays unprivileged; only that one command runs as root.
    /// </summary>
    public static Task<ProtectionInstallResult> InstallAndStartMacAsync(CancellationToken cancellationToken) =>
        InstallAndStartMacAsync(MacBundleLayout.Current, MacElevation.RunAsync, cancellationToken);

    public static async Task<ProtectionInstallResult> InstallAndStartMacAsync(
        MacBundleLayout layout,
        Func<string, string?, CancellationToken, Task<MacElevationResult>> runElevated,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(runElevated);

        if (!File.Exists(layout.DaemonPath))
        {
            return new ProtectionInstallResult(
                false,
                $"The Axiom daemon was not found at {layout.DaemonPath}. Reinstall Axiom.app.");
        }

        var command = MacElevation.BuildShellCommand(layout.DaemonPath, "--install-service");
        var result = await runElevated(
            command,
            "Axiom wants to install its background service (axiomd).",
            cancellationToken).ConfigureAwait(false);

        if (result.Succeeded)
        {
            return new ProtectionInstallResult(true, "The Axiom daemon is installed and starting.");
        }

        if (result.Cancelled)
        {
            return new ProtectionInstallResult(false, "Administrator approval was cancelled.");
        }

        var detail = result.StandardError.Trim();
        return new ProtectionInstallResult(
            false,
            detail.Length == 0
                ? $"The daemon installer exited with code {result.ExitCode}."
                : $"The daemon installer exited with code {result.ExitCode}: {detail}");
    }

    /// <summary>
    /// Linux: installs the bundled <c>axiomd</c> as the <c>axiomd.service</c> systemd unit
    /// (<c>axiomd --install-service</c>) through <c>pkexec</c>. Re-running against a newer bundle
    /// upgrades the image in <c>/usr/libexec/axiom</c>. Only that one command runs as root.
    /// </summary>
    public static Task<ProtectionInstallResult> InstallAndStartLinuxAsync(CancellationToken cancellationToken) =>
        InstallAndStartLinuxAsync(LinuxDaemonLayout.Current, LinuxElevation.RunAsync, cancellationToken);

    public static async Task<ProtectionInstallResult> InstallAndStartLinuxAsync(
        LinuxDaemonLayout layout,
        Func<IReadOnlyList<string>, CancellationToken, Task<LinuxElevationResult>> runElevated,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(runElevated);
        var daemon = layout.DaemonPath;
        if (!File.Exists(daemon))
        {
            return new ProtectionInstallResult(
                false,
                $"The Axiom daemon was not found at {layout.BundledDaemonPath}. Reinstall Axiom.");
        }

        if (!File.Exists(LinuxElevation.PkexecPath))
        {
            return new ProtectionInstallResult(
                false,
                $"{LinuxElevation.PkexecPath} is missing (polkit). Install it, or run 'sudo {daemon} --install-service' once.");
        }

        LinuxElevationResult result;
        try
        {
            result = await runElevated(LinuxElevation.BuildArguments(daemon, "--install-service"), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or IOException)
        {
            return new ProtectionInstallResult(false, $"pkexec could not start: {exception.Message}");
        }

        if (result.Succeeded)
        {
            return new ProtectionInstallResult(true, "The Axiom daemon is installed and starting.");
        }

        if (result.Cancelled)
        {
            return new ProtectionInstallResult(false, "Administrator approval was cancelled.");
        }

        var detail = result.StandardError.Trim();
        return new ProtectionInstallResult(
            false,
            detail.Length == 0
                ? $"The daemon installer exited with code {result.ExitCode}."
                : $"The daemon installer exited with code {result.ExitCode}: {detail}");
    }

    /// <summary>
    /// Stops the interactive service copy the desktop started before the Windows service existed.
    /// The installed service runs in session 0 and is never touched.
    /// </summary>
    public static void StopInteractiveServiceProcesses()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var sessionId = Process.GetCurrentProcess().SessionId;

        foreach (var process in Process.GetProcessesByName("Axiom.Service"))
        {
            try
            {
                if (process.SessionId == sessionId)
                {
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit(3000);
                }
            }
#pragma warning disable CA1031 // Best effort; the pipe reconnect handles the rest.
            catch (Exception)
#pragma warning restore CA1031
            {
            }
            finally
            {
                process.Dispose();
            }
        }
    }
}
