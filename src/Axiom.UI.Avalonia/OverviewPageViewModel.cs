// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Axiom.Presentation;
using CommunityToolkit.Mvvm.Input;

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

    public ObservableCollection<double> UploadSeries => _traffic.UploadSeries;

    public ObservableCollection<double> DownloadSeries => _traffic.DownloadSeries;

    public IReadOnlyList<string> RangeOptions { get; } = ["5m", "1h", "24h", "7d", "30d"];

    [ObservableProperty]
    private string _selectedRange = "5m";

    [ObservableProperty]
    private string _rangeNote = "Measured on active network interfaces. Per-app rates require separate telemetry.";

    [ObservableProperty]
    private string _bucketLabel = "1 s samples · rolling 5m · system-wide";

    partial void OnSelectedRangeChanged(string value) => ApplyRange(value);

    [RelayCommand]
    private void SetRange(string? range)
    {
        SelectedRange = string.IsNullOrWhiteSpace(range) ? "5m" : range;
    }

    private void ApplyRange(string range)
    {
        _traffic.SetRange(range switch
        {
            "1h" => TrafficRange.LastHour,
            "24h" => TrafficRange.LastDay,
            "7d" => TrafficRange.LastWeek,
            "30d" => TrafficRange.LastMonth,
            _ => TrafficRange.LastFiveMinutes,
        });
        BucketLabel = _traffic.BucketLabel;
        RangeNote = _traffic.RangeNote;
    }

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
    private string _sourceBadgeText = "live from IP Helper";

    [ObservableProperty]
    private string _statusText = "Starting the read-only connection monitor…";

    public void Refresh()
    {
        SourceText = _monitor.SourceName;
        SourceBadgeText = _monitor.SourceName.Contains("Service", StringComparison.OrdinalIgnoreCase)
            ? "live from the local service"
            : "live from IP Helper";
        var rows = _monitor.Connections;
        ConnectionsText = rows.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        ProcessesText = rows.Select(row => row.ProcessId).Where(pid => pid != 0).Distinct().Count()
            .ToString(System.Globalization.CultureInfo.InvariantCulture);
        LoopbackText = rows.Count(row => row.IsLoopback)
            .ToString(System.Globalization.CultureInfo.InvariantCulture);
        UploadText = ByteFormatter.Rate(_traffic.LatestUpload);
        DownloadText = ByteFormatter.Rate(_traffic.LatestDownload);
        BucketLabel = _traffic.BucketLabel;
        RangeNote = _traffic.RangeNote;
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
        BucketLabel = _traffic.BucketLabel;
        RangeNote = _traffic.RangeNote;
    }
}
