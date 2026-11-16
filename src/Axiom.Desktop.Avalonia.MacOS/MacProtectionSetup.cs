// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.MacOS;

/// <summary>Observed state of the axiomd daemon from the desktop's point of view.</summary>
public enum DaemonState
{
    Unknown,
    Running,
    InstalledNotResponding,
    NotInstalled,
}

/// <summary>
/// Replaces the Windows BundledServiceHost. On macOS the desktop never starts the daemon itself:
/// axiomd is a launchd job (<c>com.axiom.service</c>) installed once with an administrator
/// password, and the AxiomFilter system extension is managed through the app-like
/// <c>AxiomFilterHost.app</c>. This class
/// detects both, and runs the install/activation flows only after the user confirms.
/// </summary>
public sealed class MacProtectionSetup(
    ServiceStatusProbe probe,
    FilterExtensionManager filter,
    IUserInteraction ui,
    Func<bool>? isDaemonInstalled = null)
{
    private readonly Func<bool> _isDaemonInstalled = isDaemonInstalled ?? DefaultIsDaemonInstalled;
    private int _busy;

    public DaemonState Daemon { get; private set; } = DaemonState.Unknown;

    public string? DaemonVersion { get; private set; }

    public FilterExtensionStatus? Filter { get; private set; }

    public event EventHandler? Changed;

    public static string DeclinedMarkerPath => Path.Combine(AxiomPaths.UserDataDirectory, "daemon-install-declined");

    public string DaemonSummary => Daemon switch
    {
        DaemonState.Running => "Background service: running" + (DaemonVersion is null ? string.Empty : $" ({DaemonVersion})"),
        DaemonState.InstalledNotResponding => "Background service: installed, not responding",
        DaemonState.NotInstalled => "Background service: not installed",
        _ => "Background service: checking…",
    };

    public string FilterSummary => Filter is null
        ? "Network filter: checking…"
        : Filter.IsRunning
            ? "Network filter: running"
            : Filter.NeedsApproval
                ? "Network filter: waiting for approval"
                : Filter.State switch
                {
                    "not_installed" => "Network filter: not installed",
                    "installed_filter_disabled" or "disabled" => "Network filter: off",
                    "unavailable" => "Network filter: unavailable",
                    _ => "Network filter: " + Filter.State,
                };

    internal static DaemonState Classify(bool connected, bool installed) =>
        connected ? DaemonState.Running
        : installed ? DaemonState.InstalledNotResponding
        : DaemonState.NotInstalled;

    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        var snapshot = await probe.ProbeAsync(cancellationToken).ConfigureAwait(false);
        Daemon = Classify(snapshot.IsConnected, _isDaemonInstalled());
        DaemonVersion = snapshot.Capabilities is { } capabilities ? $"protocol {capabilities.ProtocolVersion}" : null;
        StartupLog.Write(
            "daemon",
            $"state={Daemon} endpoint={Axiom.Contracts.Ipc.IpcPipe.Endpoint}" +
            (snapshot.IsConnected ? string.Empty : " error=" + snapshot.LastError));
        Filter = await filter.StatusAsync(cancellationToken).ConfigureAwait(false);
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Startup check: offers the daemon install once (until the user declines), then the filter
    /// activation when the daemon runs but the filter does not.
    /// </summary>
    public async Task RunStartupChecksAsync(CancellationToken cancellationToken)
    {
        await RefreshAsync(cancellationToken).ConfigureAwait(true);
        if (Daemon == DaemonState.NotInstalled && !File.Exists(DeclinedMarkerPath))
        {
            var installed = await InstallDaemonAsync(fromStartup: true, cancellationToken).ConfigureAwait(true);
            if (!installed)
            {
                return;
            }
        }

        if (Daemon == DaemonState.Running && Filter is { IsRunning: false } status && filter.IsAvailable &&
            status.State != "unavailable")
        {
            await ActivateFilterAsync(cancellationToken).ConfigureAwait(true);
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
                "through a small background service (axiomd) that runs as a launchd daemon.\n\n" +
                "macOS will ask for an administrator password once. The Axiom window itself stays unprivileged. " +
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

            var result = await ProtectionServiceInstall.InstallAndStartMacAsync(cancellationToken).ConfigureAwait(true);
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
                "The service was installed but does not answer yet. Check /Library/Logs/Axiom and " +
                "'sudo launchctl print system/" + MacBundleLayout.DaemonLabel + "'.",
                cancellationToken).ConfigureAwait(true);
            return false;
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }

    public async Task ActivateFilterAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1)
        {
            return;
        }

        try
        {
            if (!filter.IsAvailable)
            {
                await ui.ShowMessageAsync(
                    "Network filter unavailable",
                    (Filter ?? await filter.StatusAsync(cancellationToken).ConfigureAwait(true)).Summary,
                    cancellationToken).ConfigureAwait(true);
                return;
            }

            var approved = await ui.ConfirmAsync(
                "Turn on the Axiom network filter",
                "Axiom enforces firewall rules with a macOS network extension (AxiomFilter).\n\n" +
                "macOS asks you to approve it once in " + FilterExtensionStatus.ApprovalPath +
                " (turn on Axiom and enter your password) and then to allow \"Filter Network Content\". " +
                "Axiom waits up to two minutes for the approval.",
                "Turn on",
                destructive: false,
                cancellationToken).ConfigureAwait(true);
            if (!approved)
            {
                return;
            }

            var status = await filter.ActivateAsync(cancellationToken).ConfigureAwait(true);
            Filter = status.IsRunning || !status.Ok
                ? status
                : await filter.StatusAsync(cancellationToken).ConfigureAwait(true);
            Changed?.Invoke(this, EventArgs.Empty);
            await ui.ShowMessageAsync("Axiom network filter", Filter.Summary, cancellationToken).ConfigureAwait(true);
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
            return File.Exists(MacBundleLayout.LaunchDaemonPlistPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
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
