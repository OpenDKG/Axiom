// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.History;
using Axiom.Contracts.Ipc;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Event timeline for persisted network flows. It queries the local service; without a service the
/// page says so instead of generating events. File, agent, system and blocked feeds are not stored.
/// </summary>
public sealed partial class EventsPageViewModel : PageViewModel, IActivatablePage, IDisposable
{
    private const int PageLimit = 1000;

    private const int ExportLimit = 5000;

    private readonly IServiceRequestClient? _client;
    private readonly IUserInteraction _ui;
    private readonly ConnectionActionService _actions;
    private readonly Dictionary<string, EventAppGroup> _appGroups = new(StringComparer.OrdinalIgnoreCase);
    private readonly IUiTimer? _refreshTimer;
    private readonly IUiTimer? _searchDebounce;

    public EventsPageViewModel(
        IServiceRequestClient? client,
        IUiTimerFactory timers,
        IUserInteraction ui,
        IProcessActions? processActions = null)
        : base("Network Events", "Unified timeline — network events from the local service", "E")
    {
        ArgumentNullException.ThrowIfNull(timers);
        ArgumentNullException.ThrowIfNull(ui);
        _client = client;
        _ui = ui;
        _actions = new ConnectionActionService(
            client,
            ui,
            processActions ?? new UnsupportedProcessActions());

        if (client is null)
        {
            StatusText = "Events are stored by the local service. Start this host with --service to use them.";
            IsEmpty = true;
            return;
        }

        _refreshTimer = timers.Create(TimeSpan.FromSeconds(10));
        _refreshTimer.Tick += (_, _) => _ = RefreshAsync();
        _refreshTimer.Start();

        _searchDebounce = timers.Create(TimeSpan.FromMilliseconds(400));
        _searchDebounce.Tick += (_, _) =>
        {
            _searchDebounce.StopTimer();
            _ = RefreshAsync();
        };

        _ = LoadWriteCapabilityAsync();
        _ = RefreshAsync();
    }

    public IReadOnlyList<string> Ranges { get; } = ["15m", "1h", "24h", "7d"];

    public IReadOnlyList<string> Categories { get; } = ["All", "Network"];

    public ObservableCollection<EventRowView> Rows { get; } = [];

    public ObservableCollection<EventAppGroup> AppGroups { get; } = [];

    [ObservableProperty]
    private bool _isGroupedByApp = true;

    [ObservableProperty]
    private string _selectedRange = "1h";

    [ObservableProperty]
    private string _selectedCategory = "All";

    [ObservableProperty]
    private string _searchText = string.Empty;

    [ObservableProperty]
    private string _statusText = "Loading…";

    [ObservableProperty]
    private string _databaseText = string.Empty;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private bool _isEmpty;

    [ObservableProperty]
    private int _totalCount;

    [ObservableProperty]
    private bool _canExport;

    [ObservableProperty]
    private EventRowView? _selectedEvent;

    /// <summary>
    /// True only when the service advertises firewall writes (write gate open). Block actions are
    /// disabled otherwise, matching the Applications page, instead of silently doing nothing.
    /// </summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(BlockEventOutboundCommand))]
    [NotifyCanExecuteChangedFor(nameof(BlockEventInboundCommand))]
    private bool _canWrite;

    [ObservableProperty]
    private string _writeStatusText = "Firewall writes are disabled (read-only). Block actions are unavailable.";

    /// <summary>Result of the last row action; kept separate so the periodic refresh does not erase it.</summary>
    [ObservableProperty]
    private string _actionStatusText = string.Empty;

    [ObservableProperty]
    private string _emptyHintText =
        "Network events require the local service (start with --service). File, agent, system and blocked event feeds are not recorded yet.";

    private async Task LoadWriteCapabilityAsync()
    {
        if (_client is null)
        {
            CanWrite = false;
            WriteStatusText = "Firewall writes require the local service.";
            return;
        }

        try
        {
            var capabilities = await _client
                .SendAsync<ServiceCapabilities>(IpcCommandTypes.Capabilities, null, CancellationToken.None)
                .ConfigureAwait(true);
            CanWrite = capabilities.FirewallWrites;
            WriteStatusText = CanWrite
                ? "Firewall writes are enabled for this service session."
                : "Firewall writes are disabled (read-only). Block actions are unavailable.";
        }
#pragma warning disable CA1031 // Capability probing must never crash the page.
        catch (Exception)
#pragma warning restore CA1031
        {
            CanWrite = false;
            WriteStatusText = "Firewall write capability could not be read; block actions are disabled.";
        }
    }

    [RelayCommand]
    private async Task InspectEventAsync(EventRowView? row)
    {
        var target = row ?? SelectedEvent;
        if (target is null)
        {
            return;
        }

        await _ui
            .ShowMessageAsync($"Event — {target.AppDisplayName}", target.Details, CancellationToken.None)
            .ConfigureAwait(true);
    }

    [RelayCommand]
    private Task CopyEventDetailsAsync(EventRowView? row) =>
        CopyAsync((row ?? SelectedEvent)?.Details);

    [RelayCommand]
    private Task CopyEventPathAsync(EventRowView? row) =>
        CopyAsync((row ?? SelectedEvent)?.AppPath);

    [RelayCommand]
    private Task CopyEventLocalAsync(EventRowView? row) =>
        CopyAsync((row ?? SelectedEvent)?.LocalEndpoint);

    [RelayCommand]
    private Task CopyEventRemoteAsync(EventRowView? row) =>
        CopyAsync((row ?? SelectedEvent)?.RemoteEndpoint);

    [RelayCommand(CanExecute = nameof(CanWrite))]
    private Task BlockEventOutboundAsync(EventRowView? row) =>
        BlockAsync(row, FirewallDirection.Outbound);

    [RelayCommand(CanExecute = nameof(CanWrite))]
    private Task BlockEventInboundAsync(EventRowView? row) =>
        BlockAsync(row, FirewallDirection.Inbound);

    private async Task BlockAsync(EventRowView? row, FirewallDirection direction)
    {
        if (!CanWrite)
        {
            ActionStatusText = WriteStatusText;
            return;
        }

        var target = row ?? SelectedEvent;
        if (target is null)
        {
            ActionStatusText = "Select an event first.";
            return;
        }

        ActionStatusText = await _actions
            .BlockAsync(target.AppDisplayName, target.AppPath, direction)
            .ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task EndEventTaskAsync(EventRowView? row)
    {
        var target = row ?? SelectedEvent;
        if (target is null)
        {
            ActionStatusText = "Select an event first.";
            return;
        }

        ActionStatusText = await _actions
            .EndTaskAsync(target.AppDisplayName, [target.ProcessId])
            .ConfigureAwait(true);
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
        }
        catch (Exception exception) when (exception is
                     InvalidOperationException or NotSupportedException or System.Runtime.InteropServices.ExternalException)
        {
        }
    }

    public void Activate()
    {
        _refreshTimer?.Start();
        _ = LoadWriteCapabilityAsync();
        _ = RefreshAsync();
    }

    public void Deactivate() => _refreshTimer?.StopTimer();

    public void Dispose()
    {
        _refreshTimer?.StopTimer();
        _searchDebounce?.StopTimer();
        _refreshTimer?.Dispose();
        _searchDebounce?.Dispose();
    }

    partial void OnSelectedRangeChanged(string value) => _ = RefreshAsync();

    partial void OnSelectedCategoryChanged(string value) => _ = RefreshAsync();

    partial void OnIsGroupedByAppChanged(bool value)
    {
        if (value)
        {
            RebuildGroups();
        }
    }

    partial void OnSearchTextChanged(string value)
    {
        if (_searchDebounce is null)
        {
            return;
        }

        _searchDebounce.StopTimer();
        _searchDebounce.Start();
    }

    private bool _refreshPending;

    [RelayCommand]
    private async Task RefreshAsync()
    {
        if (_client is null)
        {
            return;
        }

        if (IsLoading)
        {
            _refreshPending = true;
            return;
        }

        IsLoading = true;

        try
        {
            do
            {
                _refreshPending = false;
                var requestedRange = SelectedRange;
                var requestedSearch = SearchText;
                var requestedCategory = SelectedCategory;
                var page = await LoadAsync(PageLimit, requestedRange, requestedSearch).ConfigureAwait(true);

                if (_refreshPending ||
                    !string.Equals(SelectedRange, requestedRange, StringComparison.Ordinal) ||
                    !string.Equals(SearchText, requestedSearch, StringComparison.Ordinal) ||
                    !string.Equals(SelectedCategory, requestedCategory, StringComparison.Ordinal))
                {
                    _refreshPending = true;
                    continue;
                }

                Rows.Clear();
                foreach (var row in page.Rows)
                {
                    Rows.Add(new EventRowView(row));
                }

                TotalCount = page.TotalCount;
                DatabaseText = page.DatabasePath;
                IsEmpty = page.TotalCount == 0;
                EmptyHintText = string.IsNullOrWhiteSpace(requestedSearch)
                    ? $"No network events were recorded in the selected range ({requestedRange}). Try a longer range."
                    : $"No network events match \"{requestedSearch.Trim()}\" in the selected range ({requestedRange}). Clear or change the search.";
                CanExport = page.Rows.Count > 0;
                RebuildGroups();
                StatusText = $"{page.Rows.Count} of {page.TotalCount} network events · {requestedRange}";
            }
            while (_refreshPending);
        }
        catch (ServiceUnavailableException exception)
        {
            ClearRows(exception.Message);
        }
#pragma warning disable CA1031 // The page must not stay in "Loading" on an unexpected IPC error.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            ClearRows($"Event query failed: {exception.Message}");
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    private async Task ExportCsvAsync()
    {
        if (_client is null)
        {
            return;
        }

        try
        {
            var page = await LoadAsync(ExportLimit).ConfigureAwait(true);
            var fileName = $"axiom-events-{DateTime.Now:yyyyMMdd-HHmmss}.csv";
            var target = await _ui
                .PickSaveFileAsync(fileName, ".csv", "CSV", CancellationToken.None)
                .ConfigureAwait(true);
            if (target is null)
            {
                return;
            }

            var builder = new StringBuilder();
            builder.AppendLine("type,app,path,pid,protocol,local,remote,direction,state,quality,first_seen_utc,last_seen_utc");

            foreach (var row in page.Rows)
            {
                builder.AppendLine(string.Join(
                    ',',
                    "network",
                    Escape(row.AppDisplayName),
                    Escape(row.AppPath),
                    row.ProcessId.ToString(CultureInfo.InvariantCulture),
                    Escape(row.Protocol),
                    Escape(row.LocalEndpoint),
                    Escape(row.RemoteEndpoint),
                    Escape(row.Direction),
                    Escape(row.State),
                    Escape(row.Quality),
                    Escape(row.FirstSeenUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)),
                    Escape(row.LastSeenUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture))));
            }

            await File.WriteAllTextAsync(target, builder.ToString(), new UTF8Encoding(true))
                .ConfigureAwait(true);

            var truncated = page.TotalCount > page.Rows.Count ? " (export limit reached)" : string.Empty;
            StatusText = $"Exported {page.Rows.Count} events to {Path.GetFileName(target)}{truncated}";
        }
        catch (ServiceUnavailableException exception)
        {
            StatusText = exception.Message;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            StatusText = $"Export failed: {exception.Message}";
        }
    }

    private void ClearRows(string status)
    {
        Rows.Clear();
        AppGroups.Clear();
        TotalCount = 0;
        IsEmpty = true;
        CanExport = false;
        StatusText = status;
    }

    private void RebuildGroups()
    {
        var grouped = Rows
            .GroupBy(row => row.AppPath.Length > 0
                ? row.AppPath
                : row.AppDisplayName, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Count())
            .ThenBy(group => group.First().AppDisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var activeKeys = new HashSet<string>(grouped.Select(group => group.Key), StringComparer.OrdinalIgnoreCase);
        foreach (var stale in _appGroups.Keys.Where(key => !activeKeys.Contains(key)).ToList())
        {
            _appGroups.Remove(stale);
        }

        for (var index = AppGroups.Count - 1; index >= 0; index--)
        {
            if (!activeKeys.Contains(AppGroups[index].Key))
            {
                AppGroups.RemoveAt(index);
            }
        }

        for (var index = 0; index < grouped.Count; index++)
        {
            var group = grouped[index];
            if (!_appGroups.TryGetValue(group.Key, out var rowGroup))
            {
                rowGroup = new EventAppGroup(group.Key);
                _appGroups[group.Key] = rowGroup;
            }

            var rows = group.ToList();
            var first = rows[0];
            rowGroup.Update(
                first.ProcessId == 0 ? "Unowned kernel sockets (PID 0)" : first.AppDisplayName,
                first.ProcessId == 0 ? "No process owner" : first.AppPath,
                rows);

            var currentIndex = AppGroups.IndexOf(rowGroup);
            if (currentIndex < 0)
            {
                AppGroups.Insert(index, rowGroup);
            }
            else if (currentIndex != index)
            {
                AppGroups.Move(currentIndex, index);
            }
        }
    }

    private Task<HistoryPage> LoadAsync(int limit, string? range = null, string? searchText = null)
    {
        var activeRange = range ?? SelectedRange;
        var activeSearch = searchText ?? SearchText;
        var to = DateTimeOffset.UtcNow;
        var from = to.Subtract(RangeSpan(activeRange));

        var query = new HistoryQuery
        {
            FromUtc = from,
            ToUtc = to,
            Search = string.IsNullOrWhiteSpace(activeSearch) ? null : activeSearch.Trim(),
            Limit = limit,
            Offset = 0,
        };

        return _client!.SendAsync<HistoryPage>(IpcCommandTypes.HistoryQuery, query, CancellationToken.None);
    }

    private static TimeSpan RangeSpan(string range) => range switch
    {
        "15m" => TimeSpan.FromMinutes(15),
        "24h" => TimeSpan.FromHours(24),
        "7d" => TimeSpan.FromDays(7),
        _ => TimeSpan.FromHours(1),
    };

    private static string Escape(string value) =>
        value.Contains('"', StringComparison.Ordinal) ||
        value.Contains(',', StringComparison.Ordinal) ||
        value.Contains('\n', StringComparison.Ordinal) ||
        value.Contains('\r', StringComparison.Ordinal)
            ? $"\"{value.Replace("\"", "\"\"", StringComparison.Ordinal)}\""
            : value;
}

/// <summary>One application group in the Events grouped view.</summary>
public sealed partial class EventAppGroup : ObservableObject
{
    public EventAppGroup(string key)
    {
        Key = key;
    }

    public string Key { get; }

    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    private string _pathText = string.Empty;

    [ObservableProperty]
    private string _countText = string.Empty;

    [ObservableProperty]
    private string _summaryText = string.Empty;

    [ObservableProperty]
    private bool _isExpanded;

    public ObservableCollection<EventRowView> Events { get; } = [];

    public void Update(string name, string path, IReadOnlyList<EventRowView> rows)
    {
        Name = name;
        PathText = string.IsNullOrWhiteSpace(path) ? "Executable path not readable" : path;
        CountText = $"{rows.Count} event{(rows.Count == 1 ? string.Empty : "s")}";
        var endpoints = rows
            .Select(row => row.RemoteEndpoint)
            .Where(endpoint => !string.IsNullOrWhiteSpace(endpoint))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
        var latest = rows.Max(row => row.LastSeenUtc);
        SummaryText = $"{endpoints} remote endpoint{(endpoints == 1 ? string.Empty : "s")} · latest {latest.ToLocalTime():HH:mm:ss}";

        Events.Clear();
        foreach (var row in rows)
        {
            Events.Add(row);
        }
    }
}
