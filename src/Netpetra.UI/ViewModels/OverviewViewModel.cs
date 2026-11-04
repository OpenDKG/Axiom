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

    // Session-only events; historical investigations require an indexed service query.
    private readonly List<NewConnectionMarkerEvent> _sessionEvents = [];
    private readonly HashSet<string> _seenEventKeys = new(StringComparer.Ordinal);

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

    public IReadOnlyList<string> Ranges { get; } = ["5m", "1h", "24h", "7d", "30d"];

    public IReadOnlyList<string> RateUnits { get; } = ["Auto", "KB/s", "MB/s", "GB/s"];

    public string TrafficBadgeText => _traffic.IsLive ? "LIVE COUNTERS" : "NO BYTE HISTORY";

    public string UploadLegendText => "Upload";

    public string DownloadLegendText => "Download";

    public string ThroughputNote => _traffic.IsLive
        ? "System-wide IPv4/IPv6 interface counters are sampled once per second. Per-process bytes need ETW (FND-004)."
        : "Historical throughput is not yet captured by the service. The graph intentionally shows no fabricated rates.";

    public string ChartHelpText => _traffic.IsLive
        ? "System-wide upload and download counters with markers for newly observed connections."
        : "Historical byte samples are unavailable. Connection markers are observations from this UI session only.";

    public string ByteMeasurementText => _traffic.IsLive
        ? "system-wide counters (per-process pending)"
        : "historical byte samples unavailable";

    /// <summary>Normalised positions of connections first observed in the selected range.</summary>
    [ObservableProperty]
    private IReadOnlyList<double> _newConnectionMarkers = [];

    [ObservableProperty]
    private IReadOnlyList<string> _newConnectionMarkerLabels = [];

    [ObservableProperty]
    private IReadOnlyList<string> _newConnectionMarkerDetails = [];

    [ObservableProperty]
    private int _selectedMarkerIndex = -1;

    [ObservableProperty]
    private string _selectedConnectionDetails = "Click or hover over an event marker for connection details.";

    [ObservableProperty]
    private string _newConnectionEventsEmptyText = "No new connections in the selected range.";

    public ObservableCollection<NewConnectionMarkerEvent> NewConnectionEvents { get; } = [];

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

    [ObservableProperty]
    private string _uptimeText = "—";

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
            "30d" => TrafficRange.LastMonth,
            _ => TrafficRange.LastFiveMinutes,
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

    partial void OnSelectedMarkerIndexChanged(int value) => UpdateSelectedConnectionDetails();

    private void UpdateSelectedConnectionDetails()
    {
        SelectedConnectionDetails = SelectedMarkerIndex >= 0 &&
            SelectedMarkerIndex < NewConnectionMarkerDetails.Count
            ? NewConnectionMarkerDetails[SelectedMarkerIndex]
            : "Click or hover over an event marker for connection details.";
    }

    private void OnMonitorUpdated(object? sender, EventArgs e) => UpdateLiveCounters();

    private void UpdateLiveCounters()
    {
        ConnectionsText = _monitor.Connections.Count.ToString(CultureInfo.InvariantCulture);
        ProcessesText = _monitor.ProcessCount.ToString(CultureInfo.InvariantCulture);
        LoopbackText = _monitor.Connections.Count(connection => connection.IsLoopback).ToString(CultureInfo.InvariantCulture);
        UnownedText = AppGrouping.CountUnowned(_monitor.Connections).ToString(CultureInfo.InvariantCulture);
        NewConnectionsText = $"{_monitor.Connections.Count(connection => connection.IsNew)} new in the last 60 s";

        var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
        UptimeText = uptime.Days > 0
            ? $"{uptime.Days}d {uptime.Hours}h {uptime.Minutes}m"
            : $"{uptime.Hours}h {uptime.Minutes}m";

        var windowSeconds = SelectedRange switch
        {
            "1h" => 3600d,
            "24h" => 86400d,
            "7d" => 604800d,
            "30d" => 2592000d,
            _ => 300d,
        };
        var now = DateTimeOffset.UtcNow;

        foreach (var connection in _monitor.Connections.Where(item => item.IsNew))
        {
            var source = connection.Source;
            var key = string.Join("|", source.Protocol, source.ProcessId,
                source.LocalEndpoint, source.RemoteEndpoint, source.FirstObservedUtc.UtcTicks);
            if (!_seenEventKeys.Add(key))
            {
                continue;
            }

            _sessionEvents.Add(new NewConnectionMarkerEvent(
                0, source.FirstObservedUtc, source.AppDisplayName, source.RemoteEndpoint,
                connection.DirectionText, source.State, 0, source.ProcessId,
                source.AppPath, source.Protocol.ToString(), source.LocalEndpoint));
        }

        // Bounded session cache. Never represent it as complete seven- or thirty-day history.
        if (_sessionEvents.Count > 1024)
        {
            _sessionEvents.RemoveRange(0, _sessionEvents.Count - 1024);
            _seenEventKeys.Clear();
            foreach (var item in _sessionEvents)
            {
                _seenEventKeys.Add(string.Join("|", item.Protocol, item.ProcessId,
                    item.Local, item.Remote, item.FirstSeenUtc.UtcTicks));
            }
        }

        var events = _sessionEvents
            .Where(item => (now - item.FirstSeenUtc).TotalSeconds >= 0 &&
                           (now - item.FirstSeenUtc).TotalSeconds <= windowSeconds)
            .OrderBy(item => item.FirstSeenUtc)
            .TakeLast(8)
            .ToList();

        NewConnectionEvents.Clear();
        var positions = new double[events.Count];
        var labels = new string[events.Count];
        var details = new string[events.Count];
        for (var index = 0; index < events.Count; index++)
        {
            var item = events[index];
            positions[index] = 1d - Math.Clamp((now - item.FirstSeenUtc).TotalSeconds / windowSeconds, 0d, 1d);
            labels[index] = (index + 1).ToString(CultureInfo.InvariantCulture);
            var updated = item with { Number = index + 1, Position = positions[index] };
            NewConnectionEvents.Add(updated);
            details[index] = updated.Details;
        }

        NewConnectionMarkers = positions;
        NewConnectionMarkerLabels = labels;
        NewConnectionMarkerDetails = details;
        UpdateSelectedConnectionDetails();
        NewConnectionEventsEmptyText = events.Count == 0
            ? "No first-observed connections retained for this period in this UI session."
            : "Markers reflect first-observed connections in this UI session, not verified threats.";
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

/// <summary>One numbered marker in the chart and its human-readable event description.</summary>
public sealed record NewConnectionMarkerEvent(
    int Number,
    DateTimeOffset FirstSeenUtc,
    string App,
    string Remote,
    string Direction,
    string State,
    double Position,
    int ProcessId,
    string AppPath,
    string Protocol,
    string Local)
{
    public string TimeText => FirstSeenUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    public string Summary => $"{App} · {Direction} · {Remote} · {State}";

    public string Details =>
        $"{FirstSeenUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} · {App} (PID {ProcessId})" +
        $"\n{Protocol} {Direction}: {Local} → {Remote}" +
        $"\nState: {State} · Executable: {(string.IsNullOrEmpty(AppPath) ? "unresolved" : AppPath)}" +
        "\nCountry: unknown (GeoIP not configured) · Security: not assessed";
}
