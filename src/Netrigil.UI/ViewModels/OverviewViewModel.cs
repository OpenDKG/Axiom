// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using Netrigil.UI.Services;

namespace Netrigil.UI.ViewModels;

public sealed partial class OverviewViewModel : PageViewModel, IDisposable
{
    private readonly DemoTrafficEngine _traffic = new();

    private readonly ConnectionMonitor _monitor;

    public OverviewViewModel(ConnectionMonitor monitor)
        : base("Overview", "Live sockets from this host · throughput series is demo (FND-004)", "\uE80F")
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

    /// <summary>Demo marker positions on the time axis; real event markers arrive with FND-010.</summary>
    public IReadOnlyList<double> EventMarkers { get; } = [0.18, 0.52, 0.77];

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
    private string _uploadRateText = "—";

    [ObservableProperty]
    private string _downloadRateText = "—";

    [ObservableProperty]
    private string _bucketLabel = "1 s buckets · last 60 s";

    [ObservableProperty]
    private string _rangeNote = "Latest demo bucket; not a measurement.";

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
            "1h" => DemoTimerRange.LastHour,
            "24h" => DemoTimerRange.LastDay,
            "7d" => DemoTimerRange.LastWeek,
            _ => DemoTimerRange.LastMinute,
        });

        BucketLabel = _traffic.BucketLabel;
        OnTrafficUpdated(this, EventArgs.Empty);
    }

    private void OnMonitorUpdated(object? sender, EventArgs e) => UpdateLiveCounters();

    private void UpdateLiveCounters()
    {
        ConnectionsText = _monitor.Connections.Count.ToString(CultureInfo.InvariantCulture);
        ProcessesText = _monitor.ProcessCount.ToString(CultureInfo.InvariantCulture);
        LoopbackText = _monitor.Connections.Count(connection => connection.IsLoopback).ToString(CultureInfo.InvariantCulture);
        UnownedText = AppGrouping.CountUnowned(_monitor.Connections).ToString(CultureInfo.InvariantCulture);
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
        UploadRateText = ByteFormatter.Rate(_traffic.LatestUpload);
        DownloadRateText = ByteFormatter.Rate(_traffic.LatestDownload);
        RangeNote = _traffic.Range == DemoTimerRange.LastMinute
            ? "Updates once per second from a local generator."
            : "Fixed demo shape; live history arrives with FND-005.";
    }
}
