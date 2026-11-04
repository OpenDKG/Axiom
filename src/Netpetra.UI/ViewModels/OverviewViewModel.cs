// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using Netpetra.UI.Services;

namespace Netpetra.UI.ViewModels;

public sealed partial class OverviewViewModel : PageViewModel, IDisposable
{
    private readonly TrafficEngine _traffic = new();

    private readonly ConnectionMonitor _monitor;

    public OverviewViewModel(ConnectionMonitor monitor)
        : base("Overview", "Live sockets from this host · system-wide throughput counters", "\uE80F")
    {
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));
        monitor.Updated += OnMonitorUpdated;
        _traffic.Updated += OnTrafficUpdated;

        UpdateLiveCounters();
        UpdateMetrics();
    }

    public ObservableCollection<double> UploadSeries => _traffic.UploadSeries;

    public ObservableCollection<double> DownloadSeries => _traffic.DownloadSeries;

    public ObservableCollection<AppRow> TopApps { get; } = [];

    public IReadOnlyList<string> Ranges { get; } = ["5m", "1h", "24h", "7d"];

    public IReadOnlyList<string> RateUnits { get; } = ["Auto", "KB/s", "MB/s", "GB/s"];

    public string TrafficBadgeText => _traffic.IsLive ? "LIVE COUNTERS" : "DEMO SERIES";

    public string UploadLegendText => _traffic.IsLive ? "Upload" : "Upload (demo)";

    public string DownloadLegendText => _traffic.IsLive ? "Download" : "Download (demo)";

    public string ThroughputNote => _traffic.IsLive
        ? "System-wide IPv4/IPv6 interface counters are sampled once per second. Per-process bytes need ETW (FND-004)."
        : "This historical range is a demo shape until byte history is stored. Switch to 5m for real system-wide counters.";

    public string ChartHelpText => _traffic.IsLive
        ? "System-wide upload and download counters with markers for newly observed connections."
        : "Demo upload and download series with markers for newly observed connections.";

    public string ByteMeasurementText => _traffic.IsLive
        ? "system-wide counters (per-process pending)"
        : "system-wide live view; demo history";

    /// <summary>Normalised positions of connections first observed in the selected range.</summary>
    [ObservableProperty]
    private IReadOnlyList<double> _newConnectionMarkers = [];

    [ObservableProperty]
    private string _connectionsText = "0";

    [ObservableProperty]
    private string _processesText = "0";

    [ObservableProperty]
    private string _loopbackText = "0";

    [ObservableProperty]
    private string _ownedRulesText = "0";

    [ObservableProperty]
    private string _unownedText = "0";

    [ObservableProperty]
    private string _newConnectionsText = "0 new in the last 60 s";

    public string DatabaseText => ConnectionSourceRegistry.IsServiceMode
        ? "service-managed"
        : "not connected";

    [ObservableProperty]
    private string _sourceText = string.Empty;

    [ObservableProperty]
    private string _captureText = "—";

    [ObservableProperty]
    private string _selectedRange = "5m";

    [ObservableProperty]
    private string _selectedRateUnit = "Auto";

    [ObservableProperty]
    private string _uploadRateText = "—";

    [ObservableProperty]
    private string _downloadRateText = "—";

    [ObservableProperty]
    private string _bucketLabel = "1 s buckets · last 60 s";

    [ObservableProperty]
    private string _rangeNote = "Real system-wide interface counters.";

    public void Start() => _traffic.Start();

    public void Dispose()
    {
        _monitor.Updated -= OnMonitorUpdated;
        _traffic.Updated -= OnTrafficUpdated;
        _traffic.Dispose();
    }

    partial void OnSelectedRangeChanged(string value)
    {
        _traffic.SetRange(value switch
        {
            "1h" => TrafficRange.LastHour,
            "24h" => TrafficRange.LastDay,
            "7d" => TrafficRange.LastWeek,
            _ => TrafficRange.LastMinute,
        });

        BucketLabel = _traffic.BucketLabel;
        RangeNote = _traffic.RangeNote;
        OnPropertyChanged(nameof(TrafficBadgeText));
        OnPropertyChanged(nameof(UploadLegendText));
        OnPropertyChanged(nameof(DownloadLegendText));
        OnPropertyChanged(nameof(ThroughputNote));
        OnPropertyChanged(nameof(ChartHelpText));
        OnPropertyChanged(nameof(ByteMeasurementText));
        UpdateLiveCounters();
        OnTrafficUpdated(this, EventArgs.Empty);
    }

    partial void OnSelectedRateUnitChanged(string value) => UpdateMetrics();

    private void OnMonitorUpdated(object? sender, EventArgs e) => UpdateLiveCounters();

    private void UpdateLiveCounters()
    {
        ConnectionsText = _monitor.Connections.Count.ToString(CultureInfo.InvariantCulture);
        ProcessesText = _monitor.ProcessCount.ToString(CultureInfo.InvariantCulture);
        LoopbackText = _monitor.Connections.Count(connection => connection.IsLoopback).ToString(CultureInfo.InvariantCulture);
        UnownedText = AppGrouping.CountUnowned(_monitor.Connections).ToString(CultureInfo.InvariantCulture);
        NewConnectionsText = $"{_monitor.Connections.Count(connection => connection.IsNew)} new in the last 60 s";

        var windowSeconds = SelectedRange switch
        {
            "1h" => 3600d,
            "24h" => 86400d,
            "7d" => 604800d,
            _ => 60d,
        };
        var now = DateTimeOffset.UtcNow;
        NewConnectionMarkers = _monitor.Connections
            .Where(connection => connection.IsNew)
            .Select(connection => 1d - Math.Clamp((now - connection.FirstObservedUtc).TotalSeconds / windowSeconds, 0d, 1d))
            .OrderBy(position => position)
            .Take(30)
            .ToArray();
        SourceText = _monitor.SourceName;
        CaptureText = _monitor.LastCaptureUtc is { } captured
            ? captured.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture)
            : "—";

        var groups = AppGrouping.Group(_monitor.Connections).Take(5).ToList();
        var largest = groups.Count == 0 ? 0 : groups[0].SocketCount;

        TopApps.Clear();
        foreach (var group in groups)
        {
            var width = largest == 0 ? 0 : Math.Max(4, group.SocketCount / (double)largest * 200);
            TopApps.Add(new AppRow(group, width));
        }
    }

    private void OnTrafficUpdated(object? sender, EventArgs e) => UpdateMetrics();

    private void UpdateMetrics()
    {
        UploadRateText = ByteFormatter.Rate(_traffic.LatestUpload, SelectedRateUnit);
        DownloadRateText = ByteFormatter.Rate(_traffic.LatestDownload, SelectedRateUnit);
        RangeNote = _traffic.RangeNote;
    }
}
