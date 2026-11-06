// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Contracts.History;
using Axiom.Contracts.Ipc;
using Axiom.UI.Services;

namespace Axiom.UI.ViewModels;

/// <summary>
/// Event timeline for persisted network flows. File, agent, system and blocked events do not
/// currently have a durable event source, so those empty filters are not exposed.
/// </summary>
public sealed partial class EventsViewModel : PageViewModel, IDisposable
{
    private const int PageLimit = 1000;

    private const int ExportLimit = 5000;

    private readonly ServicePipeClient? _client;

    private readonly DispatcherTimer? _refreshTimer;

    private readonly DispatcherTimer? _searchDebounce;

    private readonly Dictionary<string, EventAppGroup> _appGroups = new(StringComparer.OrdinalIgnoreCase);

    public EventsViewModel(bool serviceMode)
        : base("Events", "Unified timeline · network events from the local service", "\uE81C")
    {
        if (!serviceMode)
        {
            StatusText = "Events are stored by the local service. Start the app with --service to use them.";
            IsEmpty = true;
            return;
        }

        _client = new ServicePipeClient();

        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(10) };
        _refreshTimer.Tick += (_, _) => _ = RefreshAsync();
        _refreshTimer.Start();

        _searchDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };
        _searchDebounce.Tick += (_, _) =>
        {
            _searchDebounce.Stop();
            _ = RefreshAsync();
        };

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

    public void Dispose()
    {
        _refreshTimer?.Stop();
        _searchDebounce?.Stop();
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

        _searchDebounce.Stop();
        _searchDebounce.Start();
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        if (_client is null || IsLoading)
        {
            return;
        }

        IsLoading = true;

        try
        {
            var page = await LoadAsync(PageLimit).ConfigureAwait(true);

            Rows.Clear();
            foreach (var row in page.Rows)
            {
                Rows.Add(new EventRowView(row));
            }

            TotalCount = page.TotalCount;
            DatabaseText = page.DatabasePath;
            IsEmpty = page.TotalCount == 0;
            CanExport = page.Rows.Count > 0;
            RebuildGroups();
            StatusText = $"{page.Rows.Count} of {page.TotalCount} network events · {SelectedRange}";
        }
        catch (ServiceUnavailableException exception)
        {
            Rows.Clear();
            AppGroups.Clear();
            TotalCount = 0;
            IsEmpty = true;
            CanExport = false;
            StatusText = exception.Message;
        }
#pragma warning disable CA1031 // The page must not stay in "Loading" on an unexpected IPC error.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            Rows.Clear();
            AppGroups.Clear();
            TotalCount = 0;
            IsEmpty = true;
            CanExport = false;
            StatusText = $"Event query failed: {exception.Message}";
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

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                FileName = $"axiom-events-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
                Filter = "CSV (*.csv)|*.csv",
                DefaultExt = ".csv",
            };

            if (dialog.ShowDialog() != true)
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
                    row.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    Escape(row.Protocol),
                    Escape(row.LocalEndpoint),
                    Escape(row.RemoteEndpoint),
                    Escape(row.Direction),
                    Escape(row.State),
                    Escape(row.Quality),
                    Escape(row.FirstSeenUtc.UtcDateTime.ToString("O")),
                    Escape(row.LastSeenUtc.UtcDateTime.ToString("O"))));
            }

            await File.WriteAllTextAsync(dialog.FileName, builder.ToString(), new UTF8Encoding(true))
                .ConfigureAwait(true);

            var truncated = page.TotalCount > page.Rows.Count ? " (export limit reached)" : string.Empty;
            StatusText = $"Exported {page.Rows.Count} events to {Path.GetFileName(dialog.FileName)}{truncated}";
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

    private Task<HistoryPage> LoadAsync(int limit)
    {
        var to = DateTimeOffset.UtcNow;
        var from = to.Subtract(RangeSpan(SelectedRange));

        var query = new HistoryQuery
        {
            FromUtc = from,
            ToUtc = to,
            Search = string.IsNullOrWhiteSpace(SearchText) ? null : SearchText.Trim(),
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
        SummaryText = $"{endpoints} remote endpoint{(endpoints == 1 ? string.Empty : "s")} \u00b7 latest {latest.ToLocalTime():HH:mm:ss}";

        Events.Clear();
        foreach (var row in rows)
        {
            Events.Add(row);
        }
    }
}
