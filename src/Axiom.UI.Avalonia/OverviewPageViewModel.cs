// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;
using CommunityToolkit.Mvvm.Input;

namespace Axiom.UI.Avalonia;

public sealed partial class OverviewPageViewModel : PageViewModel, IActivatablePage, IDisposable
{
    private readonly ConnectionMonitor _monitor;
    private readonly TrafficEngine _traffic;
    private readonly IUserInteraction _ui;
    private readonly ConnectionActionService _actions;
    private readonly IServiceRequestClient? _serviceClient;
    private readonly Action? _openPrivacyOverview;
    private readonly Action? _openPrivacySettings;
    private readonly bool _ownsConnectionsTab;
    private readonly bool _ownsAppsTab;
    private readonly bool _ownsEventsTab;
    private readonly List<NewConnectionMarkerEvent> _sessionEvents = [];
    private readonly HashSet<string> _seenEventKeys = new(StringComparer.Ordinal);
    private readonly Dictionary<string, AppRow> _topAppRows = new(StringComparer.OrdinalIgnoreCase);

    private int _rangeRequest;
    private DateTimeOffset _lastHistoryUtc = DateTimeOffset.MinValue;
    private DateTimeOffset _lastPrivacyRefreshUtc = DateTimeOffset.MinValue;
    private bool _isActive = true;
    private bool _dirty;

    public OverviewPageViewModel(
        ConnectionMonitor monitor,
        TrafficEngine traffic,
        IUserInteraction? ui = null,
        IServiceRequestClient? serviceClient = null,
        IProcessActions? processActions = null,
        PrivacyShieldPageViewModel? privacyShield = null,
        Action? openPrivacyOverview = null,
        Action? openPrivacySettings = null,
        ConnectionsPageViewModel? connectionsTab = null,
        AppsPageViewModel? appsTab = null,
        EventsPageViewModel? eventsTab = null,
        IUiTimerFactory? timers = null)
        : base("Network Dashboard", "Throughput, live connections, applications and network events", "O")
    {
        _monitor = monitor;
        _traffic = traffic;
        _ui = ui ?? new NullUserInteraction();
        _serviceClient = serviceClient;
        var resolvedProcesses = processActions ?? new UnsupportedProcessActions();
        PrivacyShield = privacyShield;
        _openPrivacyOverview = openPrivacyOverview;
        _openPrivacySettings = openPrivacySettings;
        _ownsConnectionsTab = connectionsTab is null;
        _ownsAppsTab = appsTab is null;
        _ownsEventsTab = eventsTab is null;
        ConnectionsTab = connectionsTab ?? new ConnectionsPageViewModel(_monitor, _ui, serviceClient, resolvedProcesses);
        AppsTab = appsTab ?? new AppsPageViewModel(_monitor, serviceClient, _ui, resolvedProcesses);
        EventsTab = eventsTab ?? new EventsPageViewModel(
            serviceClient,
            timers ?? FallbackTimerFactory.Instance,
            _ui,
            resolvedProcesses);
        _actions = new ConnectionActionService(
            serviceClient,
            _ui,
            resolvedProcesses);
        _monitor.Updated += OnMonitorUpdated;
        _traffic.Updated += OnTrafficUpdated;
        Refresh();
        QueuePrivacyRefresh(force: false);
    }

    /// <summary>
    /// Which protections are on (firewall write gate, firewall protection, Privacy Shield resolver,
    /// filter enforcement report); null keeps upstream's read-only wording. Set by the shell; polled
    /// on every refresh.
    /// </summary>
    public Func<OverviewProtectionState>? ProtectionState { get; set; }

    /// <summary>Upstream's original status line, kept whenever nothing is switched on.</summary>
    public const string ReadOnlyStatus = "Read-only inventory. No driver, no firewall write, no telemetry.";

    /// <summary>
    /// Status line that claims only what is on: "firewall writes enabled" only with the write gate
    /// open, "Axiom rules apply" only while firewall protection is active (and, where the OS filter
    /// reports enforcement, only when it is verified), "Privacy Shield on" only with the resolver
    /// running. With nothing on it is upstream's <see cref="ReadOnlyStatus"/>.
    /// </summary>
    public static string ComposeStatus(OverviewProtectionState? state)
    {
        if (state is null)
        {
            return ReadOnlyStatus;
        }

        var active = new List<string>();
        if (state.FirewallProtectionActive)
        {
            active.Add(state.Enforcement is null || state.Enforcement.IsEnforcementVerified
                ? "Axiom rules apply"
                : $"Axiom rules {state.Enforcement.EnforcementClause("network filter")}");
        }

        if (state.PrivacyShieldActive)
        {
            active.Add("Privacy Shield on");
        }

        if (active.Count == 0)
        {
            return state.FirewallWritesEnabled
                ? "Firewall writes enabled; no Axiom rules active. No telemetry."
                : ReadOnlyStatus;
        }

        active.Add(state.FirewallWritesEnabled ? "firewall writes enabled" : "no firewall write");
        return "Protection active: " + string.Join("; ", active) + ". No telemetry.";
    }

    public ConnectionsPageViewModel ConnectionsTab { get; }

    public AppsPageViewModel AppsTab { get; }

    public EventsPageViewModel EventsTab { get; }

    [ObservableProperty]
    private int _selectedMonitoringTabIndex;

    public PrivacyShieldPageViewModel? PrivacyShield { get; }

    public bool HasPrivacyShield => PrivacyShield is not null;

    [RelayCommand]
    private void OpenPrivacyOverview() => _openPrivacyOverview?.Invoke();

    [RelayCommand]
    private void OpenPrivacySettings() => _openPrivacySettings?.Invoke();

    public void Activate()
    {
        _isActive = true;
        if (_dirty)
        {
            _dirty = false;
            Refresh();
        }

        (ConnectionsTab as IActivatablePage)?.Activate();
        (AppsTab as IActivatablePage)?.Activate();
        (EventsTab as IActivatablePage)?.Activate();
        QueuePrivacyRefresh(force: true);
    }

    private void QueuePrivacyRefresh(bool force)
    {
        if (PrivacyShield is null || !_isActive)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        if (!force && now - _lastPrivacyRefreshUtc < TimeSpan.FromSeconds(2))
        {
            return;
        }

        _lastPrivacyRefreshUtc = now;
        _ = PrivacyShield.RefreshSummaryAsync();
    }

    public void Deactivate()
    {
        _isActive = false;
        (ConnectionsTab as IActivatablePage)?.Deactivate();
        (AppsTab as IActivatablePage)?.Deactivate();
        (EventsTab as IActivatablePage)?.Deactivate();
    }

    public ObservableCollection<ConnectionRow> Connections => _monitor.Connections;

    public ObservableCollection<NewConnectionMarkerEvent> NewConnectionEvents { get; } = [];

    public ObservableCollection<AppRow> TopApps { get; } = [];

    [ObservableProperty]
    private string _newConnectionsText = "0 new in the last 60 s";

    [ObservableProperty]
    private string _newConnectionEventsEmptyText =
        "No first-observed connections retained for this period in this UI session.";

    [ObservableProperty]
    private bool _hasNewConnectionEvents;

    [ObservableProperty]
    private NewConnectionMarkerEvent? _selectedEvent;

    [ObservableProperty]
    private string _selectedEventDetails =
        "Select a first-observed connection to see details.";

    private string? _selectedEventKey;
    private bool _restoringEvents;

    partial void OnSelectedEventChanged(NewConnectionMarkerEvent? value)
    {
        if (_restoringEvents)
        {
            return;
        }

        _selectedEventKey = value is null ? null : EventKey(value);
        SelectedEventDetails = value?.Details ?? "Select a first-observed connection to see details.";
    }

    private static string EventKey(NewConnectionMarkerEvent item) =>
        string.Join(
            "|",
            item.Protocol,
            item.ProcessId,
            item.Local,
            item.Remote,
            item.FirstSeenUtc.UtcTicks);

    public ObservableCollection<double> UploadSeries => _traffic.UploadSeries;

    public ObservableCollection<double> DownloadSeries => _traffic.DownloadSeries;

    public bool HasLiveTraffic => _traffic.IsLive;

    public IReadOnlyList<string> RangeOptions { get; } = ["5m", "1h", "12h", "24h", "7d", "30d"];

    [ObservableProperty]
    private string _selectedRange = "5m";

    [ObservableProperty]
    private string _rangeNote = "Measured on active network interfaces. Per-app rates require separate telemetry.";

    [ObservableProperty]
    private string _bucketLabel = "1 s samples · rolling 5m · system-wide";

    [ObservableProperty]
    private bool _showNoDataOverlay;

    [ObservableProperty]
    private string _noDataText = "No measured throughput yet.";

    partial void OnSelectedRangeChanged(string value) => ApplyRange(value);

    [RelayCommand]
    private void SetRange(string? range)
    {
        SelectedRange = string.IsNullOrWhiteSpace(range) ? "5m" : range;
    }

    private void ApplyRange(string range)
    {
        var trafficRange = MapRange(range);
        _traffic.SetRange(trafficRange);
        BucketLabel = _traffic.BucketLabel;
        RangeNote = _traffic.RangeNote;
        OnPropertyChanged(nameof(HasLiveTraffic));
        UpdateLiveCounters();

        var generation = ++_rangeRequest;
        if (trafficRange == TrafficRange.LastFiveMinutes)
        {
            ShowNoDataOverlay = false;
            return;
        }

        _ = LoadHistoryAsync(trafficRange, generation);
    }

    private static TrafficRange MapRange(string range) => range switch
    {
        "1h" => TrafficRange.LastHour,
        "12h" => TrafficRange.LastTwelveHours,
        "24h" => TrafficRange.LastDay,
        "7d" => TrafficRange.LastWeek,
        "30d" => TrafficRange.LastMonth,
        _ => TrafficRange.LastFiveMinutes,
    };

    private static TimeSpan RangeSpan(TrafficRange range) => range switch
    {
        TrafficRange.LastHour => TimeSpan.FromHours(1),
        TrafficRange.LastTwelveHours => TimeSpan.FromHours(12),
        TrafficRange.LastDay => TimeSpan.FromDays(1),
        TrafficRange.LastWeek => TimeSpan.FromDays(7),
        TrafficRange.LastMonth => TimeSpan.FromDays(30),
        _ => TimeSpan.FromMinutes(5),
    };

    private static string RangeLabel(TrafficRange range) => range switch
    {
        TrafficRange.LastHour => "1h",
        TrafficRange.LastTwelveHours => "12h",
        TrafficRange.LastDay => "24h",
        TrafficRange.LastWeek => "7d",
        TrafficRange.LastMonth => "30d",
        _ => "5m",
    };

    /// <summary>
    /// Loads persisted system-wide throughput from the service. Only the 5-minute window is
    /// sampled in this process; every longer range is real history or an explicit gap.
    /// </summary>
    private async Task LoadHistoryAsync(TrafficRange range, int generation)
    {
        _lastHistoryUtc = DateTimeOffset.UtcNow;
        ShowNoDataOverlay = true;
        NoDataText = $"Loading {RangeLabel(range)} system-wide throughput from the Axiom service…";

        if (_serviceClient is null)
        {
            ShowHistoryFailure("the local Axiom service is not connected");
            return;
        }

        try
        {
            var now = DateTimeOffset.UtcNow;
            var history = await _serviceClient
                .SendAsync<ThroughputHistory>(
                    IpcCommandTypes.ThroughputHistory,
                    new ThroughputHistoryQuery
                    {
                        FromUtc = now.Subtract(RangeSpan(range)),
                        ToUtc = now,
                        BucketSeconds = TrafficEngine.BucketSecondsFor(range),
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            if (generation != _rangeRequest)
            {
                return;
            }

            var upload = new List<double>(history.Points.Count);
            var download = new List<double>(history.Points.Count);
            foreach (var point in history.Points)
            {
                // Rate = bytes / seconds actually observed, so a partially sampled bucket is not
                // drawn as a full-bucket average and an unmeasured bucket stays a gap.
                var measured = point.MeasuredSeconds > 0.5;
                upload.Add(measured ? point.UploadBytes / point.MeasuredSeconds : double.NaN);
                download.Add(measured ? point.DownloadBytes / point.MeasuredSeconds : double.NaN);
            }

            _traffic.SetHistory(range, history.BucketSeconds, upload, download, history.Detail);
            BucketLabel = _traffic.BucketLabel;
            RangeNote = _traffic.RangeNote;
            ShowNoDataOverlay = !_traffic.HasHistoryData;
            NoDataText = _traffic.HasHistoryData
                ? string.Empty
                : "No system-wide throughput recorded for this range yet. History starts when the Axiom service first runs and is stored locally for 30 days.";
        }
        catch (Exception exception) when (exception is
                     ServiceUnavailableException or TimeoutException or
                     System.Text.Json.JsonException or System.IO.IOException)
        {
            if (generation != _rangeRequest)
            {
                return;
            }

            ShowHistoryFailure(exception.Message);
        }
    }

    private void ShowHistoryFailure(string reason)
    {
        _traffic.SetHistoryUnavailable($"History unavailable: {reason}");
        BucketLabel = _traffic.BucketLabel;
        RangeNote = _traffic.RangeNote;
        ShowNoDataOverlay = true;
        NoDataText = $"System-wide throughput history is unavailable because {reason}";
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
            ? ComposeStatus(ProtectionState?.Invoke())
            : $"Monitor unavailable: {_monitor.LastError}";

        UpdateLiveCounters();

        // A selected historical range refreshes itself without polling the service every second.
        if (!_traffic.IsLive &&
            DateTimeOffset.UtcNow - _lastHistoryUtc >= TimeSpan.FromSeconds(30))
        {
            _ = LoadHistoryAsync(_traffic.Range, ++_rangeRequest);
        }
    }

    private void RecordSessionEvents()
    {
        foreach (var connection in _monitor.Connections.Where(item => item.IsNew))
        {
            var source = connection.Source;
            var key = string.Join(
                "|",
                source.Protocol,
                source.ProcessId,
                source.LocalEndpoint,
                source.RemoteEndpoint,
                source.FirstObservedUtc.UtcTicks);
            if (!_seenEventKeys.Add(key))
            {
                continue;
            }

            _sessionEvents.Add(new NewConnectionMarkerEvent(
                0,
                source.FirstObservedUtc,
                source.AppDisplayName,
                source.RemoteEndpoint,
                connection.DirectionText,
                source.State,
                source.ProcessId,
                source.AppPath,
                source.Protocol.ToString(),
                source.LocalEndpoint));
        }

        // Bounded session cache; never presented as complete history.
        if (_sessionEvents.Count > 1024)
        {
            _sessionEvents.RemoveRange(0, _sessionEvents.Count - 1024);
            _seenEventKeys.Clear();
            foreach (var item in _sessionEvents)
            {
                _seenEventKeys.Add(
                    string.Join("|", item.Protocol, item.ProcessId, item.Local, item.Remote, item.FirstSeenUtc.UtcTicks));
            }
        }
    }

    private void UpdateLiveCounters()
    {
        var window = SelectedRange switch
        {
            "1h" => TimeSpan.FromHours(1),
            "12h" => TimeSpan.FromHours(12),
            "24h" => TimeSpan.FromDays(1),
            "7d" => TimeSpan.FromDays(7),
            "30d" => TimeSpan.FromDays(30),
            _ => TimeSpan.FromMinutes(5),
        };
        var now = DateTimeOffset.UtcNow;

        NewConnectionsText =
            $"{_monitor.Connections.Count(connection => connection.IsNew)} new in the last 60 s";

        RecordSessionEvents();

        var selectedKey = _selectedEventKey;
        var events = _sessionEvents
            .Where(item => now - item.FirstSeenUtc >= TimeSpan.Zero &&
                           now - item.FirstSeenUtc <= window)
            .OrderBy(item => item.FirstSeenUtc)
            .TakeLast(8)
            .ToList();

        // A busy host can produce more than eight events in a few seconds. Keep the user's
        // selected event in the visible list so the details panel does not vanish on the next poll.
        if (selectedKey is not null &&
            !events.Any(item => EventKey(item) == selectedKey) &&
            _sessionEvents.FirstOrDefault(item =>
                EventKey(item) == selectedKey &&
                now - item.FirstSeenUtc >= TimeSpan.Zero &&
                now - item.FirstSeenUtc <= window) is { } pinned)
        {
            events.Add(pinned);
            events = events.OrderBy(item => item.FirstSeenUtc).ToList();
        }

        var numberedEvents = new List<NewConnectionMarkerEvent>(events.Count);
        for (var index = 0; index < events.Count; index++)
        {
            numberedEvents.Add(events[index] with { Number = index + 1 });
        }

        // Only rebuild NewConnectionEvents when the list actually changes so open context menus
        // and item containers are not destroyed on every 1-second poll.
        if (!NewConnectionEvents.SequenceEqual(numberedEvents))
        {
            _restoringEvents = true;
            try
            {
                NewConnectionEvents.Clear();
                foreach (var item in numberedEvents)
                {
                    NewConnectionEvents.Add(item);
                }

                SelectedEvent = selectedKey is null
                    ? null
                    : NewConnectionEvents.FirstOrDefault(item => EventKey(item) == selectedKey);
                SelectedEventDetails = SelectedEvent?.Details
                    ?? "Select a first-observed connection to see details.";
            }
            finally
            {
                _restoringEvents = false;
            }
        }

        HasNewConnectionEvents = events.Count > 0;
        NewConnectionEventsEmptyText = events.Count == 0
            ? "No first-observed connections retained for this period in this UI session."
            : "Markers reflect first-observed connections in this UI session, not verified threats.";

        var groups = AppGrouping.Group(_monitor.Connections).Take(5).ToList();
        var largest = groups.Count == 0 ? 0 : groups[0].SocketCount;
        var desiredRows = new List<AppRow>(groups.Count);
        var activeKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in groups)
        {
            var width = largest == 0 ? 0 : Math.Max(4, group.SocketCount / (double)largest * 200);
            activeKeys.Add(group.Key);
            if (_topAppRows.TryGetValue(group.Key, out var existing))
            {
                existing.Update(group, width);
                desiredRows.Add(existing);
            }
            else
            {
                var created = new AppRow(group, width);
                _topAppRows[group.Key] = created;
                desiredRows.Add(created);
            }
        }

        foreach (var staleKey in _topAppRows.Keys.Where(key => !activeKeys.Contains(key)).ToList())
        {
            _topAppRows.Remove(staleKey);
        }

        if (!TopApps.SequenceEqual(desiredRows))
        {
            TopApps.Clear();
            foreach (var row in desiredRows)
            {
                TopApps.Add(row);
            }
        }
    }

    [ObservableProperty]
    private string _actionStatusText = string.Empty;

    [ObservableProperty]
    private ConnectionRow? _selectedSocket;

    [RelayCommand]
    private Task CopyRowAsync(ConnectionRow? row) => CopyAsync(row?.RowTooltip);

    [RelayCommand]
    private Task CopyPathAsync(ConnectionRow? row) => CopyAsync(row?.PathText);

    [RelayCommand]
    private Task CopyRemoteAsync(ConnectionRow? row) => CopyAsync(row?.RemoteEndpoint);

    [RelayCommand]
    private async Task BlockOutboundAsync(ConnectionRow? row)
    {
        if (row is not null)
        {
            ActionStatusText = await _actions
                .BlockAsync(row.AppDisplayName, row.PathText, FirewallDirection.Outbound)
                .ConfigureAwait(true);
        }
    }

    [RelayCommand]
    private async Task BlockInboundAsync(ConnectionRow? row)
    {
        if (row is not null)
        {
            ActionStatusText = await _actions
                .BlockAsync(row.AppDisplayName, row.PathText, FirewallDirection.Inbound)
                .ConfigureAwait(true);
        }
    }

    [RelayCommand]
    private async Task EndTaskAsync(ConnectionRow? row)
    {
        var target = row ?? SelectedSocket;
        if (target is not null)
        {
            ActionStatusText = await _actions
                .EndProcessAsync(target.AppDisplayName, target.ProcessId)
                .ConfigureAwait(true);
        }
    }

    [RelayCommand]
    private Task CopyStatusAsync() =>
        CopyAsync(string.IsNullOrWhiteSpace(ActionStatusText) ? StatusText : ActionStatusText);

    [RelayCommand]
    private async Task InspectMarkerEventAsync(NewConnectionMarkerEvent? item)
    {
        var target = item ?? SelectedEvent;
        if (target is null)
        {
            return;
        }

        await _ui
            .ShowMessageAsync($"Event #{target.Number} — {target.App}", target.Details, CancellationToken.None)
            .ConfigureAwait(true);
    }

    [RelayCommand]
    private Task CopyMarkerEventAsync(NewConnectionMarkerEvent? item) =>
        CopyAsync((item ?? SelectedEvent)?.Details);

    [RelayCommand]
    private Task CopyMarkerPathAsync(NewConnectionMarkerEvent? item) =>
        CopyAsync((item ?? SelectedEvent)?.AppPath);

    [RelayCommand]
    private Task CopyMarkerRemoteAsync(NewConnectionMarkerEvent? item) =>
        CopyAsync((item ?? SelectedEvent)?.Remote);

    [RelayCommand]
    private async Task BlockMarkerOutboundAsync(NewConnectionMarkerEvent? item)
    {
        var target = item ?? SelectedEvent;
        if (target is not null)
        {
            ActionStatusText = await _actions
                .BlockAsync(target.App, target.AppPath, FirewallDirection.Outbound)
                .ConfigureAwait(true);
        }
    }

    [RelayCommand]
    private async Task BlockMarkerInboundAsync(NewConnectionMarkerEvent? item)
    {
        var target = item ?? SelectedEvent;
        if (target is not null)
        {
            ActionStatusText = await _actions
                .BlockAsync(target.App, target.AppPath, FirewallDirection.Inbound)
                .ConfigureAwait(true);
        }
    }

    [RelayCommand]
    private async Task EndMarkerTaskAsync(NewConnectionMarkerEvent? item)
    {
        var target = item ?? SelectedEvent;
        if (target is not null)
        {
            ActionStatusText = await _actions
                .EndProcessAsync(target.App, target.ProcessId)
                .ConfigureAwait(true);
        }
    }

    [RelayCommand]
    private Task CopyTopAppPathAsync(AppRow? app) => CopyAsync(app?.PathText);

    [RelayCommand]
    private async Task BlockTopAppOutboundAsync(AppRow? app)
    {
        if (app is not null)
        {
            ActionStatusText = await _actions
                .BlockAsync(app.Name, app.PathText, FirewallDirection.Outbound)
                .ConfigureAwait(true);
        }
    }

    [RelayCommand]
    private async Task BlockTopAppInboundAsync(AppRow? app)
    {
        if (app is not null)
        {
            ActionStatusText = await _actions
                .BlockAsync(app.Name, app.PathText, FirewallDirection.Inbound)
                .ConfigureAwait(true);
        }
    }

    [RelayCommand]
    private async Task EndTopAppTaskAsync(AppRow? app)
    {
        if (app is not null)
        {
            ActionStatusText = await _actions
                .EndApplicationAsync(app.Name, app.ProcessIds)
                .ConfigureAwait(true);
        }
    }

    private async Task CopyAsync(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value == "—")
        {
            return;
        }

        try
        {
            await _ui.CopyTextAsync(value, CancellationToken.None).ConfigureAwait(true);
            ActionStatusText = "Copied to the clipboard.";
        }
        catch (Exception exception) when (exception is
                     InvalidOperationException or NotSupportedException or System.Runtime.InteropServices.ExternalException)
        {
            ActionStatusText = "Clipboard is unavailable.";
        }
    }

    public void Dispose()
    {
        _monitor.Updated -= OnMonitorUpdated;
        _traffic.Updated -= OnTrafficUpdated;
        if (_ownsConnectionsTab)
        {
            ConnectionsTab.Dispose();
        }

        if (_ownsAppsTab)
        {
            AppsTab.Dispose();
        }

        if (_ownsEventsTab)
        {
            EventsTab.Dispose();
        }
    }

    private sealed class FallbackTimerFactory : IUiTimerFactory
    {
        public static FallbackTimerFactory Instance { get; } = new();

        public IUiTimer Create(TimeSpan interval) => new FallbackTimer(interval);

        private sealed class FallbackTimer(TimeSpan interval) : IUiTimer
        {
            public TimeSpan Interval { get; set; } = interval;

            public bool IsEnabled { get; private set; }

            public event EventHandler? Tick
            {
                add { }
                remove { }
            }

            public void Start() => IsEnabled = true;

            public void StopTimer() => IsEnabled = false;

            public void Dispose()
            {
            }
        }
    }

    private void OnMonitorUpdated(object? sender, EventArgs e)
    {
        if (!_isActive)
        {
            RecordSessionEvents();
            _dirty = true;
            return;
        }

        Refresh();
        QueuePrivacyRefresh(force: false);
    }

    private void OnTrafficUpdated(object? sender, EventArgs e)
    {
        if (!_isActive)
        {
            _dirty = true;
            return;
        }

        UploadText = ByteFormatter.Rate(_traffic.LatestUpload);
        DownloadText = ByteFormatter.Rate(_traffic.LatestDownload);
        BucketLabel = _traffic.BucketLabel;
        RangeNote = _traffic.RangeNote;
    }
}
