// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;
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

    private bool _syncingTheme;

    public MainViewModel(ConnectionMonitor monitor)
    {
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));
        _overview = new OverviewViewModel(monitor);
        Themes =
        [
            new ThemeOption(AppTheme.Dark, "Dark · Graphite"),
            new ThemeOption(AppTheme.DarkMidnight, "Dark · Midnight"),
            new ThemeOption(AppTheme.Light, "Light · Clean"),
            new ThemeOption(AppTheme.LightWarm, "Light · Warm"),
        ];
        _selectedTheme = Themes.First(theme => theme.Value == ThemeManager.Current);

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
            new SupportViewModel(),
            new SettingsViewModel(monitor),
        ];

        _selectedPage = _overview;
        _overview.TrafficSampled += OnOverviewTrafficSampled;
        _overview.Start();

        monitor.Updated += OnMonitorUpdated;
        monitor.Start();

        ThemeManager.Changed += OnThemeChanged;
    }

    public double CurrentUploadBytesPerSecond => _overview.LatestMeasuredUploadBytesPerSecond;

    public double CurrentDownloadBytesPerSecond => _overview.LatestMeasuredDownloadBytesPerSecond;

    public event EventHandler? TrayStatusUpdated;

    public IReadOnlyList<PageViewModel> Pages { get; }

    [ObservableProperty]
    private PageViewModel _selectedPage;

    partial void OnSelectedPageChanged(PageViewModel value)
    {
        foreach (var page in Pages.OfType<IActivatablePage>())
        {
            page.Deactivate();
        }

        if (value is IActivatablePage active)
        {
            active.Activate();
        }
    }

    public IReadOnlyList<ThemeOption> Themes { get; }

    [ObservableProperty]
    private ThemeOption? _selectedTheme;

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
    private void OpenGitHub()
    {
        try
        {
            Process.Start(new ProcessStartInfo("https://github.com/a-51-50/Netpetra")
            {
                UseShellExecute = true,
            });
        }
        catch (Win32Exception)
        {
        }
        catch (InvalidOperationException)
        {
        }
    }

    [RelayCommand]
    private void OpenSupport()
    {
        var support = Pages.OfType<SupportViewModel>().FirstOrDefault();
        if (support is not null)
        {
            SelectedPage = support;
        }
    }

    public void Dispose()
    {
        ThemeManager.Changed -= OnThemeChanged;
        _overview.TrafficSampled -= OnOverviewTrafficSampled;
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

    private void OnOverviewTrafficSampled(object? sender, EventArgs e) =>
        TrayStatusUpdated?.Invoke(this, EventArgs.Empty);

    private void OnMonitorUpdated(object? sender, EventArgs e)
    {
        OnPropertyChanged(nameof(StatusMonitoringText));
        TrayStatusUpdated?.Invoke(this, EventArgs.Empty);
    }

    private void OnThemeChanged(object? sender, EventArgs e)
    {
        _syncingTheme = true;
        try
        {
            SelectedTheme = Themes.FirstOrDefault(theme => theme.Value == ThemeManager.Current) ?? Themes[0];
        }
        finally
        {
            _syncingTheme = false;
        }
    }

    partial void OnSelectedThemeChanged(ThemeOption? value)
    {
        if (_syncingTheme || value is null || value.Value == ThemeManager.Current)
        {
            return;
        }

        _syncingTheme = true;
        try
        {
            ThemeManager.Apply(value.Value);
        }
        finally
        {
            _syncingTheme = false;
        }
    }
}

public sealed record ThemeOption(AppTheme Value, string Label)
{
    public override string ToString() => Label;
}
