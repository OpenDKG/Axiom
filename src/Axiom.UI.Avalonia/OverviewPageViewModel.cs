// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

public sealed partial class OverviewPageViewModel : PageViewModel, IDisposable
{
    private readonly ConnectionMonitor _monitor;
    private readonly TrafficEngine _traffic;

    public OverviewPageViewModel(ConnectionMonitor monitor, TrafficEngine traffic)
        : base("Overview", "Live sockets and system-wide interface counters", "O")
    {
        _monitor = monitor;
        _traffic = traffic;
        _monitor.Updated += OnMonitorUpdated;
        _traffic.Updated += OnTrafficUpdated;
        Refresh();
    }

    public ObservableCollection<ConnectionRow> Connections => _monitor.Connections;

    [ObservableProperty]
    private string _connectionsText = "0";

    [ObservableProperty]
    private string _processesText = "0";

    [ObservableProperty]
    private string _loopbackText = "0";

    [ObservableProperty]
    private string _uploadText = "—";

    [ObservableProperty]
    private string _downloadText = "—";

    [ObservableProperty]
    private string _sourceText = "IP Helper · TCP/UDP IPv4/IPv6";

    [ObservableProperty]
    private string _statusText = "Starting the read-only connection monitor…";

    public void Refresh()
    {
        var rows = _monitor.Connections;
        ConnectionsText = rows.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        ProcessesText = rows.Select(row => row.ProcessId).Where(pid => pid != 0).Distinct().Count()
            .ToString(System.Globalization.CultureInfo.InvariantCulture);
        LoopbackText = rows.Count(row => row.IsLoopback)
            .ToString(System.Globalization.CultureInfo.InvariantCulture);
        UploadText = ByteFormatter.Rate(_traffic.LatestUpload);
        DownloadText = ByteFormatter.Rate(_traffic.LatestDownload);
        StatusText = _monitor.LastError is null
            ? "Read-only inventory. No driver, no firewall write, no telemetry."
            : $"Monitor unavailable: {_monitor.LastError}";
    }

    public void Dispose()
    {
        _monitor.Updated -= OnMonitorUpdated;
        _traffic.Updated -= OnTrafficUpdated;
    }

    private void OnMonitorUpdated(object? sender, EventArgs e) => Refresh();

    private void OnTrafficUpdated(object? sender, EventArgs e)
    {
        UploadText = ByteFormatter.Rate(_traffic.LatestUpload);
        DownloadText = ByteFormatter.Rate(_traffic.LatestDownload);
    }
}
