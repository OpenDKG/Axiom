// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Netpetra.Contracts.Ipc;
using Netpetra.UI.Services;

namespace Netpetra.UI.ViewModels;

public sealed partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly ConnectionMonitor _monitor;

    private readonly OverviewViewModel _overview;

    private readonly ServicePipeClient? _client;

    public MainViewModel(ConnectionMonitor monitor)
    {
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));
        _overview = new OverviewViewModel(monitor);

        if (ConnectionSourceRegistry.IsServiceMode)
        {
            _client = new ServicePipeClient();
            _ = LoadCapabilitiesAsync();
        }

        var security = new SecurityViewModel();

        Pages =
        [
            _overview,
            new LiveConnectionsViewModel(monitor),
            new AppsViewModel(monitor, ConnectionSourceRegistry.IsServiceMode),
            new EventsViewModel(ConnectionSourceRegistry.IsServiceMode),
            new AgentsViewModel(security),
            new FirewallRulesViewModel(ConnectionSourceRegistry.IsServiceMode),
            new FilesViewModel(() => SelectedPage = security),
            security,
            new SettingsViewModel(monitor),
        ];

        _selectedPage = _overview;
        _overview.Start();

        monitor.Updated += OnMonitorUpdated;
        monitor.Start();

        ThemeManager.Changed += OnThemeChanged;
        UpdateThemeToggleLabel();
    }

    public IReadOnlyList<PageViewModel> Pages { get; }

    [ObservableProperty]
    private PageViewModel _selectedPage;

    [ObservableProperty]
    private string _themeToggleLabel = "Switch to light theme";

    [ObservableProperty]
    private bool _firewallWritesEnabled;

    public string StatusMonitoringText => _monitor.LastError is null
        ? $"Monitoring: live · {_monitor.PollInterval.TotalSeconds:0} s"
        : "Monitoring: unavailable";

    public string StatusModeText => ConnectionSourceRegistry.IsServiceMode
        ? "Service monitor"
        : "Read-only monitor";

    public string StatusLiveText => ConnectionSourceRegistry.IsServiceMode
        ? "LIVE · SERVICE"
        : "LIVE · READ-ONLY";

    public string VersionText =>
        $"v{typeof(MainViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"}";

    public string StatusFirewallBadgeText => FirewallWritesEnabled
        ? "Firewall writes enabled"
        : "Firewall writes disabled";

    public string StatusFirewallText => FirewallWritesEnabled
        ? "Firewall control: writes enabled"
        : "Firewall control: read-only";

    public string StatusIpcText => ConnectionSourceRegistry.IsServiceMode
        ? "IPC: local service"
        : "IPC: not connected";

    public string FooterText => ConnectionSourceRegistry.IsServiceMode
        ? "Local service · no driver · no telemetry · no remote access."
        : "In-process monitor · no service · no driver · no telemetry.";

    public string StatusStorageText => ConnectionSourceRegistry.IsServiceMode
        ? "Database: service-managed"
        : "Database: not connected";

    public string StatusDataSourceText => ConnectionSourceRegistry.IsLive
        ? "Data source: LIVE (read-only)"
        : "Data source: DEMO";

    [RelayCommand]
    private void ToggleTheme() => ThemeManager.Toggle();

    public void Dispose()
    {
        ThemeManager.Changed -= OnThemeChanged;
        _monitor.Updated -= OnMonitorUpdated;

        foreach (var disposable in Pages.OfType<IDisposable>())
        {
            disposable.Dispose();
        }

        _monitor.Dispose();
    }

    private async Task LoadCapabilitiesAsync()
    {
        if (_client is null)
        {
            return;
        }

        try
        {
            var capabilities = await _client
                .SendAsync<ServiceCapabilities>(IpcCommandTypes.Capabilities, null, CancellationToken.None)
                .ConfigureAwait(true);

            FirewallWritesEnabled = capabilities.FirewallWrites;
        }
        catch (ServiceUnavailableException)
        {
            FirewallWritesEnabled = false;
        }
#pragma warning disable CA1031 // A status query must not crash the shell.
        catch (Exception)
#pragma warning restore CA1031
        {
            FirewallWritesEnabled = false;
        }
    }

    partial void OnFirewallWritesEnabledChanged(bool value)
    {
        OnPropertyChanged(nameof(StatusFirewallBadgeText));
        OnPropertyChanged(nameof(StatusFirewallText));
    }

    private void OnMonitorUpdated(object? sender, EventArgs e) =>
        OnPropertyChanged(nameof(StatusMonitoringText));

    private void OnThemeChanged(object? sender, EventArgs e) => UpdateThemeToggleLabel();

    private void UpdateThemeToggleLabel() =>
        ThemeToggleLabel = ThemeManager.Current is AppTheme.Dark or AppTheme.DarkMidnight
            ? "Switch to light theme"
            : "Switch to dark theme";
}
