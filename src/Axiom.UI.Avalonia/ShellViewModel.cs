// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Avalonia shell for the first migration slice. The WPF shell remains the reference until every
/// page is ported; this shell deliberately exposes only the pages that have real implementations.
/// </summary>
public sealed partial class ShellViewModel : ObservableObject, IDisposable
{
    private readonly ConnectionMonitor _monitor;
    private readonly TrafficEngine _traffic;
    private readonly ServiceStatusProbe? _serviceProbe;
    private readonly CancellationTokenSource _cancellation = new();
    private DateTimeOffset _lastProbeUtc = DateTimeOffset.MinValue;
    private bool _isProbing;

    public ShellViewModel(
        IConnectionSnapshotSource source,
        IUiTimerFactory timers,
        ServiceStatusProbe? serviceProbe = null,
        IServiceRequestClient? serviceClient = null,
        IUserInteraction? userInteraction = null,
        IProcessActions? processActions = null,
        IThemeService? themeService = null,
        IAutostartService? autostartService = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(timers);
        _monitor = new ConnectionMonitor(source, timers);
        _traffic = new TrafficEngine(timers);
        _serviceProbe = serviceProbe;
        IsServiceMode = source is ServiceSnapshotSource;
        var interaction = userInteraction ?? new NullUserInteraction();
        Overview = new OverviewPageViewModel(_monitor, _traffic);
        Connections = new ConnectionsPageViewModel(_monitor);
        Apps = new AppsPageViewModel(
            _monitor,
            IsServiceMode ? serviceClient : null,
            interaction,
            processActions ?? new UnsupportedProcessActions());
        Events = new EventsPageViewModel(
            IsServiceMode ? serviceClient : null,
            timers,
            interaction);
        Firewall = new FirewallPageViewModel(IsServiceMode ? serviceClient : null, interaction);
        Support = new SupportPageViewModel(interaction);
        Settings = new SettingsPageViewModel(
            _monitor,
            IsServiceMode,
            themeService ?? new FixedThemeService(),
            autostartService ?? new UnsupportedAutostartService());
        Pages = [Overview, Connections, Apps, Events, Firewall, Support, Settings];
        _selectedPage = Overview;
        _monitor.Updated += OnMonitorUpdated;
    }

    public OverviewPageViewModel Overview { get; }

    public ConnectionsPageViewModel Connections { get; }

    public AppsPageViewModel Apps { get; }

    public EventsPageViewModel Events { get; }

    public FirewallPageViewModel Firewall { get; }

    public SupportPageViewModel Support { get; }

    public SettingsPageViewModel Settings { get; }

    public ObservableCollection<PageViewModel> Pages { get; }

    [ObservableProperty]
    private PageViewModel _selectedPage;

    [ObservableProperty]
    private string _statusMonitoringText = "Monitoring: starting";

    [ObservableProperty]
    private string _statusSourceText = "Data source: starting";

    [ObservableProperty]
    private string _statusIpcText = "IPC: not connected";

    [ObservableProperty]
    private string _statusStorageText = "Database: not connected";

    [ObservableProperty]
    private string _statusFirewallText = "Firewall writes: read-only";

    [ObservableProperty]
    private string _footerText = "Local only · no driver · no telemetry · no remote access.";

    public bool IsServiceMode { get; }

    public ServiceStatusSnapshot? ServiceStatus { get; private set; }

    public string VersionText =>
        $"v{typeof(ShellViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"}";

    public void Start()
    {
        _monitor.Start();
        _traffic.Start();
        Overview.Refresh();
        RefreshStatus();
        _ = ProbeServiceAsync(force: true);
    }

    public void Dispose()
    {
        _monitor.Updated -= OnMonitorUpdated;
        _cancellation.Cancel();
        _cancellation.Dispose();
        Overview.Dispose();
        Connections.Dispose();
        Apps.Dispose();
        Events.Dispose();
        Firewall.Dispose();
        Settings.Dispose();
        _traffic.Dispose();
        _monitor.Dispose();
    }

    private void OnMonitorUpdated(object? sender, EventArgs e)
    {
        RefreshStatus();
        _ = ProbeServiceAsync();
    }

    private void RefreshStatus()
    {
        StatusMonitoringText = _monitor.LastError is null
            ? $"Monitoring: live · {_monitor.PollInterval.TotalSeconds:0} s · {_monitor.SourceName}"
            : $"Monitoring: unavailable · {_monitor.LastError}";

        StatusSourceText = IsServiceMode
            ? "Data source: local service (read-only)"
            : "Data source: in-process IP Helper (read-only)";

        StatusFirewallText = ServiceStatus?.Capabilities?.FirewallWrites == true
            ? "Firewall writes: enabled for this service session"
            : "Firewall writes: read-only";

        StatusStorageText = ServiceStatus?.IsConnected == true
            ? "Database: service-managed"
            : "Database: not connected";

        StatusIpcText = ServiceStatus switch
        {
            { IsConnected: true, Capabilities: { } capabilities } =>
                $"IPC: local service · contract v{capabilities.ProtocolVersion}",
            { IsConnected: false } => "IPC: service offline",
            _ => IsServiceMode ? "IPC: probing local service" : "IPC: not connected",
        };

        FooterText = IsServiceMode
            ? "Local service · no driver · no telemetry · no remote access."
            : "In-process monitor · no service · no driver · no telemetry.";
    }

    private async Task ProbeServiceAsync(bool force = false)
    {
        if (_serviceProbe is null || _isProbing)
        {
            return;
        }

        // The monitor ticks every second; probing the pipe at the same rate would double the
        // request load for a status string that rarely changes.
        if (!force && DateTimeOffset.UtcNow - _lastProbeUtc < TimeSpan.FromSeconds(5))
        {
            return;
        }

        _isProbing = true;
        _lastProbeUtc = DateTimeOffset.UtcNow;
        try
        {
            var status = await _serviceProbe.ProbeAsync(_cancellation.Token).ConfigureAwait(true);
            ServiceStatus = status;
            RefreshStatus();
        }
        catch (OperationCanceledException)
        {
            // Shutting down.
        }
        finally
        {
            _isProbing = false;
        }
    }
}
