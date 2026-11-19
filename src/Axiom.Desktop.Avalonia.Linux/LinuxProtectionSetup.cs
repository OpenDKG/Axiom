// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.Linux;

/// <summary>Observed state of the axiomd daemon from the desktop's point of view.</summary>
public enum DaemonState
{
    Unknown,
    Running,
    InstalledNotResponding,
    NotInstalled,
}

/// <summary>
/// Replaces the Windows BundledServiceHost. On Linux the desktop never starts the daemon itself:
/// axiomd is a systemd unit installed once through pkexec (polkit). This class detects it through
/// the IPC socket, the unit file and <c>systemctl is-active</c>, and runs the install only after
/// the user confirms. Re-running the install against a newer bundle upgrades the image.
/// </summary>
public sealed class LinuxProtectionSetup(
    ServiceStatusProbe probe,
    IUserInteraction ui,
    Func<bool>? isDaemonInstalled = null,
    Func<string>? unitState = null,
    bool? packageManaged = null)
{
    private readonly Func<bool> _isDaemonInstalled = isDaemonInstalled ?? DefaultIsDaemonInstalled;
    private readonly Func<string> _unitState = unitState ?? ReadUnitState;
    private readonly bool _packageManaged = packageManaged ?? LinuxDaemonLayout.Current.IsPackageManaged;
    private int _busy;

    public DaemonState Daemon { get; private set; } = DaemonState.Unknown;

    public string? DaemonVersion { get; private set; }

    public string UnitState { get; private set; } = "unknown";

    public event EventHandler? Changed;

    public static string DeclinedMarkerPath => Path.Combine(LinuxPaths.StateDirectory, "daemon-install-declined");

    public string DaemonSummary => Daemon switch
    {
        DaemonState.Running => "Background service: running" + (DaemonVersion is null ? string.Empty : $" ({DaemonVersion})"),
        DaemonState.InstalledNotResponding => $"Background service: installed, not responding (unit {UnitState})",
        DaemonState.NotInstalled => "Background service: not installed",
        _ => "Background service: checking…",
    };

    internal static DaemonState Classify(bool connected, bool installed) =>
        connected ? DaemonState.Running
        : installed ? DaemonState.InstalledNotResponding
        : DaemonState.NotInstalled;

    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        var snapshot = await probe.ProbeAsync(cancellationToken).ConfigureAwait(false);
        Daemon = Classify(snapshot.IsConnected, _isDaemonInstalled());
        UnitState = _unitState();
        DaemonVersion = snapshot.Capabilities is { } capabilities ? $"protocol {capabilities.ProtocolVersion}" : null;
        StartupLog.Write(
            "daemon",
            $"state={Daemon} unit={UnitState} endpoint={Axiom.Contracts.Ipc.IpcPipe.Endpoint}" +
            (snapshot.IsConnected ? string.Empty : " error=" + snapshot.LastError));
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// The startup offer is made only for a bundle the user runs by hand (unpacked publish tree):
    /// the daemon is missing and the user has not declined before. A package install
    /// (<see cref="LinuxDaemonLayout.IsPackageManaged"/>) registered the daemon in its postinst,
    /// so the desktop never prompts for pkexec at first launch; the Shield page still offers a
    /// manual install/upgrade for a damaged unit.
    /// </summary>
    internal static bool ShouldOfferInstallAtStartup(DaemonState state, bool declined, bool packageManaged) =>
        state == DaemonState.NotInstalled && !declined && !packageManaged;

    /// <summary>Startup check: offers the daemon install once (until the user declines).</summary>
    public async Task RunStartupChecksAsync(CancellationToken cancellationToken)
    {
        await RefreshAsync(cancellationToken).ConfigureAwait(true);
        if (ShouldOfferInstallAtStartup(Daemon, File.Exists(DeclinedMarkerPath), _packageManaged))
        {
            await InstallDaemonAsync(fromStartup: true, cancellationToken).ConfigureAwait(true);
        }
        else if (_packageManaged && Daemon != DaemonState.Running)
        {
            StartupLog.Write("daemon", $"package-managed install ({LinuxDaemonLayout.PackagePrefix}); no startup install offer, unit={UnitState}");
        }
    }

    public async Task<bool> InstallDaemonAsync(bool fromStartup, CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1)
        {
            return false;
        }

        try
        {
            var approved = await ui.ConfirmAsync(
                "Install the Axiom background service",
                "Axiom monitors connections, keeps history and enforces firewall and Privacy Shield rules " +
                "through a small background service (axiomd) that runs as a systemd unit.\n\n" +
                "polkit will ask for an administrator password once. The Axiom window itself stays unprivileged. " +
                "Without the service Axiom can only show this window.",
                "Install",
                destructive: false,
                cancellationToken).ConfigureAwait(true);
            if (!approved)
            {
                if (fromStartup)
                {
                    MarkDeclined();
                }

                return false;
            }

            var result = await ProtectionServiceInstall.InstallAndStartLinuxAsync(cancellationToken).ConfigureAwait(true);
            StartupLog.Write("daemon", "install: " + result.Message);
            if (!result.Success)
            {
                await ui.ShowMessageAsync("Background service not installed", result.Message, cancellationToken)
                    .ConfigureAwait(true);
                return false;
            }

            TryDelete(DeclinedMarkerPath);
            for (var attempt = 0; attempt < 20; attempt++)
            {
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(true);
                await RefreshAsync(cancellationToken).ConfigureAwait(true);
                if (Daemon == DaemonState.Running)
                {
                    return true;
                }
            }

            await ui.ShowMessageAsync(
                "Background service not responding",
                "The service was installed but does not answer yet. " + PlatformText.ServiceCheckHint,
                cancellationToken).ConfigureAwait(true);
            return false;
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }

    private static bool DefaultIsDaemonInstalled()
    {
        try
        {
            return File.Exists(LinuxDaemonLayout.UnitFilePath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary><c>systemctl is-active axiomd</c>: active, inactive, failed, activating… or "unknown".</summary>
    internal static string ReadUnitState()
    {
        try
        {
            var startInfo = new ProcessStartInfo("/usr/bin/systemctl")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            startInfo.ArgumentList.Add("is-active");
            startInfo.ArgumentList.Add(LinuxDaemonLayout.UnitName);
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return "unknown";
            }

            var output = process.StandardOutput.ReadToEnd().Trim();
            return process.WaitForExit(3000) && output.Length > 0 ? output : "unknown";
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return "unknown";
        }
    }

    private static void MarkDeclined()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(DeclinedMarkerPath)!);
            File.WriteAllText(DeclinedMarkerPath, DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}
