// SPDX-License-Identifier: GPL-3.0-or-later
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Netrigil.UI.Services;

namespace Netrigil.UI.ViewModels;

public sealed partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly ConnectionMonitor _monitor;

    private readonly OverviewViewModel _overview;

    public MainViewModel(ConnectionMonitor monitor)
    {
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));
        _overview = new OverviewViewModel(monitor);

        Pages =
        [
            _overview,
            new LiveConnectionsViewModel(monitor),
            new AppsViewModel(monitor, ConnectionSourceRegistry.IsServiceMode),
            new EventsViewModel(ConnectionSourceRegistry.IsServiceMode),
            new FirewallRulesViewModel(ConnectionSourceRegistry.IsServiceMode),
            new FilesViewModel(),
            new SecurityViewModel(),
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

    public string StatusMonitoringText => _monitor.LastError is null
        ? $"Monitoring: live · {_monitor.PollInterval.TotalSeconds:0} s"
        : "Monitoring: unavailable";

    public string StatusFirewallText => "Firewall control: not implemented";

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

    private void OnMonitorUpdated(object? sender, EventArgs e) =>
        OnPropertyChanged(nameof(StatusMonitoringText));

    private void OnThemeChanged(object? sender, EventArgs e) => UpdateThemeToggleLabel();

    private void UpdateThemeToggleLabel() =>
        ThemeToggleLabel = ThemeManager.Current == AppTheme.Dark
            ? "Switch to light theme"
            : "Switch to dark theme";
}
