// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Netpetra.Contracts.Monitoring;
using Netpetra.UI.Services;

namespace Netpetra.UI.ViewModels;

public sealed partial class LiveConnectionsViewModel : PageViewModel, IDisposable
{
    private const string AllProtocols = "All";

    private readonly ConnectionMonitor _monitor;

    private readonly CollectionView _view;

    private readonly Dictionary<string, ConnectionAppGroup> _appGroups = new(StringComparer.OrdinalIgnoreCase);

    public LiveConnectionsViewModel(ConnectionMonitor monitor)
        : base("Connections", "Sockets read from this Windows host · read-only, poll-only", "\uE774")
    {
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));
        _view = (CollectionView)CollectionViewSource.GetDefaultView(monitor.Connections);
        _view.Filter = MatchesFilter;
        _view.SortDescriptions.Clear();
        _view.SortDescriptions.Add(new SortDescription(nameof(ConnectionRow.StateRank), ListSortDirection.Ascending));
        _view.SortDescriptions.Add(new SortDescription(nameof(ConnectionRow.AppDisplayName), ListSortDirection.Ascending));
        monitor.Updated += OnMonitorUpdated;
        UpdateStatus();
        RebuildGroups();
    }

    public ObservableCollection<ConnectionRow> Connections => _monitor.Connections;

    public ICollectionView View => _view;

    public IReadOnlyList<string> ProtocolOptions { get; } = [AllProtocols, "TCP", "UDP"];

    [ObservableProperty]
    private string _protocolFilter = AllProtocols;

    [ObservableProperty]
    private string _searchText = string.Empty;

    [ObservableProperty]
    private bool _onlyNew;

    [ObservableProperty]
    private bool _onlyLoopback;

    [ObservableProperty]
    private string _visibleRowsText = string.Empty;

    [ObservableProperty]
    private bool _isEmpty;

    [ObservableProperty]
    private string _sourceText = string.Empty;

    [ObservableProperty]
    private string _lastPollText = string.Empty;

    [ObservableProperty]
    private string _statusLine = string.Empty;

    [ObservableProperty]
    private string _limitationsText = string.Empty;

    [ObservableProperty]
    private string _errorText = string.Empty;

    [ObservableProperty]
    private bool _hasError;

    [ObservableProperty]
    private ConnectionRow? _selectedConnection;

    [ObservableProperty]
    private bool _hasRelated;

    [ObservableProperty]
    private string _relatedTitle = string.Empty;

    public ObservableCollection<ConnectionRow> RelatedConnections { get; } = [];

    public ObservableCollection<ConnectionAppGroup> AppGroups { get; } = [];

    [ObservableProperty]
    private bool _isGroupedByApp = true;

    public void Dispose() => _monitor.Updated -= OnMonitorUpdated;

    partial void OnProtocolFilterChanged(string value) => ApplyFilter();

    partial void OnSearchTextChanged(string value) => ApplyFilter();

    partial void OnOnlyNewChanged(bool value) => ApplyFilter();

    partial void OnOnlyLoopbackChanged(bool value) => ApplyFilter();

    partial void OnSelectedConnectionChanged(ConnectionRow? value) => RefreshRelated();

    partial void OnIsGroupedByAppChanged(bool value)
    {
        if (value)
        {
            HasRelated = false;
            RebuildGroups();
            UpdateStatus();
        }
        else if (SelectedConnection is not null)
        {
            RefreshRelated();
        }
    }

    private void RefreshRelated()
    {
        RelatedConnections.Clear();

        if (IsGroupedByApp)
        {
            HasRelated = false;
            RelatedTitle = string.Empty;
            return;
        }

        if (SelectedConnection is null)
        {
            HasRelated = false;
            RelatedTitle = string.Empty;
            return;
        }

        var source = SelectedConnection.Source;
        var matches = Connections
            .Where(candidate => !ReferenceEquals(candidate, SelectedConnection))
            .Where(candidate => source.AppPath.Length > 0
                ? string.Equals(candidate.Source.AppPath, source.AppPath, StringComparison.OrdinalIgnoreCase)
                : candidate.Source.ProcessId == source.ProcessId)
            .Take(25)
            .ToList();

        foreach (var match in matches)
        {
            RelatedConnections.Add(match);
        }

        HasRelated = matches.Count > 0;
        RelatedTitle = matches.Count == 0
            ? string.Empty
            : $"Other connections from {SelectedConnection.AppDisplayName} ({matches.Count})";
    }

    [RelayCommand]
    private void ResetFilters()
    {
        SearchText = string.Empty;
        ProtocolFilter = AllProtocols;
        OnlyNew = false;
        OnlyLoopback = false;
        ApplyFilter();
    }

    private void OnMonitorUpdated(object? sender, EventArgs e)
    {
        if (HasActiveFilters)
        {
            _view.Refresh();
        }

        UpdateStatus();

        if (SelectedConnection is not null)
        {
            RefreshRelated();
        }

        if (IsGroupedByApp)
        {
            RebuildGroups();
        }
    }

    private bool HasActiveFilters =>
        SearchText.Length > 0 ||
        !string.Equals(ProtocolFilter, AllProtocols, StringComparison.Ordinal) ||
        OnlyNew ||
        OnlyLoopback;

    private void ApplyFilter()
    {
        _view.Refresh();
        UpdateStatus();
        if (IsGroupedByApp)
        {
            RebuildGroups();
        }
    }

    private void RebuildGroups()
    {
        var grouped = _view
            .Cast<ConnectionRow>()
            .GroupBy(row => row.Source.AppPath.Length > 0
                ? row.Source.AppPath
                : $"pid:{row.Source.ProcessId}", StringComparer.OrdinalIgnoreCase)
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
                rowGroup = new ConnectionAppGroup(group.Key);
                _appGroups[group.Key] = rowGroup;
            }

            var rows = group.ToList();
            var first = rows[0];
            rowGroup.Update(
                first.Source.ProcessId == 0 ? "Unowned kernel sockets (PID 0)" : first.AppDisplayName,
                first.Source.ProcessId == 0 ? "No process owner" : first.Source.AppPath,
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

        if (IsGroupedByApp)
        {
            VisibleRowsText = $"Showing {AppGroups.Count} applications \u00b7 {_view.Count} sockets";
        }
    }

    private void UpdateStatus()
    {
        SourceText = _monitor.SourceName;
        LastPollText = _monitor.LastCaptureUtc is { } captured
            ? $"Last poll {captured.ToLocalTime():HH:mm:ss} · {_monitor.PollInterval.TotalSeconds:0} s interval · " +
              $"{Connections.Count} sockets / {_monitor.ProcessCount} processes"
            : "Waiting for the first poll…";

        LimitationsText = string.Join(" ", _monitor.Limitations);
        HasError = _monitor.LastError is not null;
        ErrorText = _monitor.LastError ?? string.Empty;
        VisibleRowsText = $"Showing {_view.Count} of {Connections.Count} sockets · row virtualization on";
        IsEmpty = _view.Count == 0;
        StatusLine = $"{SourceText} · {LastPollText}";
    }

    private bool MatchesFilter(object item)
    {
        if (item is not ConnectionRow row)
        {
            return false;
        }

        if (!string.Equals(ProtocolFilter, AllProtocols, StringComparison.Ordinal))
        {
            var wantsTcp = string.Equals(ProtocolFilter, "TCP", StringComparison.Ordinal);
            var isTcp = row.Protocol == TransportProtocol.Tcp;
            if (wantsTcp != isTcp)
            {
                return false;
            }
        }

        if (OnlyNew && !row.IsNew)
        {
            return false;
        }

        if (OnlyLoopback && !row.IsLoopback)
        {
            return false;
        }

        var query = SearchText.Trim();
        return query.Length == 0 || row.SearchBlob.Contains(query, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>One application group in the Connections grouped view.</summary>
public sealed partial class ConnectionAppGroup : ObservableObject
{
    public ConnectionAppGroup(string key)
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

    public ObservableCollection<ConnectionRow> Connections { get; } = [];

    public void Update(string name, string path, IReadOnlyList<ConnectionRow> rows)
    {
        Name = name;
        PathText = string.IsNullOrWhiteSpace(path) ? "Executable path not readable" : path;
        CountText = $"{rows.Count} socket{(rows.Count == 1 ? string.Empty : "s")}";
        var tcp = rows.Count(row => row.Protocol == TransportProtocol.Tcp);
        var udp = rows.Count - tcp;
        var states = rows
            .GroupBy(row => row.State, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Count())
            .Take(2)
            .Select(group => $"{group.Key} {group.Count()}");
        SummaryText = $"{tcp} TCP \u00b7 {udp} UDP \u00b7 {string.Join(" \u00b7 ", states)}";

        // Keep the group's DataGrid scroll position and selection stable across one-second polls.
        var desired = new HashSet<ConnectionRow>(rows, ReferenceEqualityComparer.Instance);
        for (var index = Connections.Count - 1; index >= 0; index--)
        {
            if (!desired.Contains(Connections[index]))
            {
                Connections.RemoveAt(index);
            }
        }

        var existing = new HashSet<ConnectionRow>(Connections, ReferenceEqualityComparer.Instance);
        foreach (var row in rows)
        {
            if (existing.Add(row))
            {
                Connections.Add(row);
            }
        }
    }
}
