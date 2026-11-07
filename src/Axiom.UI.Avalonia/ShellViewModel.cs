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

    public ShellViewModel(IConnectionSnapshotSource source, IUiTimerFactory timers)
    {
        _monitor = new ConnectionMonitor(source, timers);
        _traffic = new TrafficEngine(timers);
        Overview = new OverviewPageViewModel(_monitor, _traffic);
        Connections = new ConnectionsPageViewModel(_monitor);
        Pages = [Overview, Connections];
        _selectedPage = Overview;
    }

    public OverviewPageViewModel Overview { get; }

    public ConnectionsPageViewModel Connections { get; }

    public ObservableCollection<PageViewModel> Pages { get; }

    [ObservableProperty]
    private PageViewModel _selectedPage;

    public string VersionText =>
        $"v{typeof(ShellViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"}";

    public string StatusMonitoringText => _monitor.LastError is null
        ? $"Monitoring: live · {_monitor.PollInterval.TotalSeconds:0} s"
        : "Monitoring: unavailable";

    public string StatusSourceText => "In-process IP Helper · read-only";
    public string StatusIpcText => "IPC: not connected";
    public string StatusStorageText => "Database: not connected";

    public void Start()
    {
        _monitor.Start();
        _traffic.Start();
        Overview.Refresh();
    }

    public void Dispose()
    {
        Overview.Dispose();
        Connections.Dispose();
        _traffic.Dispose();
        _monitor.Dispose();
    }
}
