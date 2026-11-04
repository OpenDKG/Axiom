// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Netpetra.UI.Services;

namespace Netpetra.UI.ViewModels;

public sealed partial class OverviewViewModel : PageViewModel, IDisposable
{
    private readonly TrafficEngine _traffic = new();

    private readonly ConnectionMonitor _monitor;

    // Session-only events; historical investigations require an indexed service query.
    private readonly List<NewConnectionMarkerEvent> _sessionEvents = [];
    private readonly HashSet<string> _seenEventKeys = new(StringComparer.Ordinal);
    private string? _selectedEventKey;

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

    public bool IsTrafficLive => _traffic.IsLive;

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

    // A 5-minute session-only time cursor. This does not claim persisted historical flows.
    [ObservableProperty]
    private double _timelineCursorPosition = 300;

    [ObservableProperty]
    private string _timelineCursorTimeText = "Now";

    [ObservableProperty]
    private string _timelineFocusText = "Waiting for first-observed connection events.";

    [ObservableProperty]
    private string _timelineEndpointCountText = "0 observed endpoints";

    public ObservableCollection<TimelineEndpointRow> TimelineEndpoints { get; } = [];

    [RelayCommand]
    private void JumpToNow() => TimelineCursorPosition = 300;

    partial void OnTimelineCursorPositionChanged(double value) => UpdateTimelineFocus();

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
    private string _bucketLabel = "1 s samples · rolling 5m · system-wide";

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
        OnPropertyChanged(nameof(IsTrafficLive));
        OnPropertyChanged(nameof(UploadLegendText));
        OnPropertyChanged(nameof(DownloadLegendText));
        OnPropertyChanged(nameof(ThroughputNote));
        OnPropertyChanged(nameof(ChartHelpText));
        OnPropertyChanged(nameof(ByteMeasurementText));
        UpdateLiveCounters();
        OnTrafficUpdated(this, EventArgs.Empty);
    }

    partial void OnSelectedRateUnitChanged(string value) => UpdateMetrics();

    partial void OnSelectedMarkerIndexChanged(int value)
    {
        _selectedEventKey = value >= 0 && value < NewConnectionEvents.Count
            ? EventKey(NewConnectionEvents[value])
            : null;
        UpdateSelectedConnectionDetails();
    }

    private static string EventKey(NewConnectionMarkerEvent item) =>
        string.Join("|", item.Protocol, item.ProcessId,
            item.Local, item.Remote, item.FirstSeenUtc.UtcTicks);

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
                _seenEventKeys.Add(EventKey(item));
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
        if (_selectedEventKey is not null)
        {
            var matchingIndex = NewConnectionEvents
                .Select((item, index) => (Item: item, Index: index))
                .Where(entry => EventKey(entry.Item) == _selectedEventKey)
                .Select(entry => entry.Index)
                .DefaultIfEmpty(-1)
                .First();
            SelectedMarkerIndex = matchingIndex;
        }

        UpdateSelectedConnectionDetails();
        NewConnectionEventsEmptyText = events.Count == 0
            ? "No first-observed connections retained for this period in this UI session."
            : "Markers reflect first-observed connections in this UI session, not verified threats.";
        UpdateTimelineFocus();
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

    private void UpdateTimelineFocus()
    {
        TimelineEndpoints.Clear();

        if (!IsTrafficLive)
        {
            TimelineCursorTimeText = "No recorded historical throughput";
            TimelineFocusText = "The time cursor currently supports only the locally observed 5-minute session. Persistent history will be delivered separately.";
            TimelineEndpointCountText = "Historical connection events not loaded";
            return;
        }

        var secondsAgo = 300 - Math.Clamp(TimelineCursorPosition, 0, 300);
        var selectedTime = DateTimeOffset.UtcNow.AddSeconds(-secondsAgo);
        TimelineCursorTimeText = string.Format(
            CultureInfo.InvariantCulture, "{0:HH:mm:ss} local · {1:0} s ago",
            selectedTime.ToLocalTime(), secondsAgo);

        // This is a first-observed event explorer, not a snapshot of all sockets active
        // at the selected time. Events can be missed by polling or app restarts.
        var near = _sessionEvents
            .Where(item => Math.Abs((selectedTime - item.FirstSeenUtc).TotalSeconds) <= 10)
            .OrderByDescending(item => item.FirstSeenUtc)
            .ToList();

        TimelineFocusText = near.Count == 0
            ? "No first-observed sockets in this ±10-second window. This does not mean there was no network traffic."
            : string.Format(CultureInfo.InvariantCulture,
                "{0} first-observed sockets within ±10 s (session-only; not a threat verdict).", near.Count);

        var grouped = near
            .GroupBy(item => (item.App, item.ProcessId, item.Remote, item.Protocol))
            .Select(group => new TimelineEndpointRow(
                group.Key.App, group.Key.ProcessId, group.Key.Protocol,
                group.Key.Remote, group.Count(), group.Max(item => item.FirstSeenUtc)))
            .OrderByDescending(item => item.LastObservedUtc)
            .Take(12);

        foreach (var endpoint in grouped)
        {
            TimelineEndpoints.Add(endpoint);
        }

        TimelineEndpointCountText = TimelineEndpoints.Count == 0
            ? "No observed endpoints at cursor"
            : $"{TimelineEndpoints.Count} app/remote groups at cursor";
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

/// <summary>Aggregate of first-observed session events at the selected time cursor.</summary>
public sealed record TimelineEndpointRow(
    string App,
    int ProcessId,
    string Protocol,
    string Remote,
    int ObservedCount,
    DateTimeOffset LastObservedUtc)
{
    public string AppText => $"{App} · PID {ProcessId} · {Protocol}";

    public string ObservationsText => ObservedCount == 1
        ? "1 observed socket"
        : $"{ObservedCount} observed sockets";

    public string Detail => $"{AppText}\nRemote: {Remote}\nLast first-seen: {LastObservedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}\nCountry: not resolved · Security: not assessed";
}
