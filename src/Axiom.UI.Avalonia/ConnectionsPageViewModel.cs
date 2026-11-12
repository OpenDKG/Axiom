// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Contracts.Firewall;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

public sealed partial class ConnectionsPageViewModel : PageViewModel, IActivatablePage, IDisposable
{
    // The live status line refreshes every poll; keep an action result visible long enough to read.
    private static readonly TimeSpan ActionStatusHold = TimeSpan.FromSeconds(15);
    private DateTime _actionStatusUntilUtc = DateTime.MinValue;

    private readonly ConnectionMonitor _monitor;
    private readonly IUserInteraction _ui;
    private readonly ConnectionActionService _actions;
    private readonly Dictionary<string, ConnectionAppGroup> _groupIndex =
        new(StringComparer.OrdinalIgnoreCase);
    private string? _selectedKey;
    private bool _rebuilding;
    private bool _isActive = true;
    private bool _dirty;

    public ConnectionsPageViewModel(
        ConnectionMonitor monitor,
        IUserInteraction? ui = null,
        IServiceRequestClient? serviceClient = null,
        IProcessActions? processActions = null)
        : base("Live Connections", $"Sockets read from this {PlatformText.HostKind} — read-only", "C")
    {
        _monitor = monitor;
        _ui = ui ?? new NullUserInteraction();
        _actions = new ConnectionActionService(
            serviceClient,
            _ui,
            processActions ?? new UnsupportedProcessActions());
        _monitor.Updated += OnUpdated;
        ApplyFilters();
    }

    public ObservableCollection<ConnectionRow> Connections => VisibleConnections;

    public ObservableCollection<ConnectionRow> VisibleConnections { get; } = [];

    public ObservableCollection<ConnectionAppGroup> Groups { get; } = [];

    public IReadOnlyList<string> ProtocolOptions { get; } = ["All", "TCP", "UDP"];

    public IReadOnlyList<string> GroupSortOptions { get; } = ["Total traffic", "Sent", "Received", "Sockets", "Name"];

    [ObservableProperty]
    private bool _isGroupedByApp = true;

    [ObservableProperty]
    private string _groupSort = "Total traffic";

    [ObservableProperty]
    private bool _groupSortDescending = true;

    public string GroupSortDirectionText => GroupSortDescending ? "Descending" : "Ascending";

    [ObservableProperty]
    private string _statusText = "Connecting to the socket inventory…";

    [ObservableProperty]
    private string _visibleRowsText = "0 sockets";

    [ObservableProperty]
    private bool _isEmpty;

    [ObservableProperty]
    private string _searchText = string.Empty;

    [ObservableProperty]
    private string _protocolFilter = "All";

    [ObservableProperty]
    private bool _onlyNew;

    [ObservableProperty]
    private bool _onlyLoopback;

    [ObservableProperty]
    private ConnectionRow? _selectedConnection;

    partial void OnSearchTextChanged(string value) => ApplyFilters();

    partial void OnProtocolFilterChanged(string value) => ApplyFilters();

    partial void OnOnlyNewChanged(bool value) => ApplyFilters();

    partial void OnOnlyLoopbackChanged(bool value) => ApplyFilters();

    partial void OnGroupSortChanged(string value) => ApplyFilters();

    partial void OnGroupSortDescendingChanged(bool value)
    {
        OnPropertyChanged(nameof(GroupSortDirectionText));
        ApplyFilters();
    }

    [RelayCommand]
    private void ToggleGroupSortDirection() => GroupSortDescending = !GroupSortDescending;

    partial void OnSelectedConnectionChanged(ConnectionRow? value)
    {
        // Rebuilding VisibleConnections every poll clears the ListBox selection; keep the key so
        // ApplyFilters can restore it instead of forgetting what the user picked.
        if (!_rebuilding)
        {
            _selectedKey = value is null ? null : SelectionKey(value);
        }
    }

    private static string SelectionKey(ConnectionRow row) =>
        $"{row.ProcessId}|{row.ProtocolText}|{row.LocalEndpoint}|{row.Source.RemoteEndpoint}";

    [RelayCommand]
    private Task CopyRowAsync(ConnectionRow? row) => CopyAsync(row, row?.RowTooltip);

    [RelayCommand]
    private Task CopyPathAsync(ConnectionRow? row) => CopyAsync(row, row?.PathText);

    [RelayCommand]
    private Task CopyLocalAsync(ConnectionRow? row) => CopyAsync(row, row?.LocalEndpoint);

    [RelayCommand]
    private Task CopyRemoteAsync(ConnectionRow? row) => CopyAsync(row, row?.RemoteEndpoint);

    [RelayCommand]
    private async Task BlockOutboundAsync(ConnectionRow? row)
    {
        if (row is not null)
        {
            StatusText = await _actions
                .BlockAsync(row.AppDisplayName, row.PathText, FirewallDirection.Outbound)
                .ConfigureAwait(true);
            _actionStatusUntilUtc = DateTime.UtcNow + ActionStatusHold;
        }
    }

    [RelayCommand]
    private async Task BlockInboundAsync(ConnectionRow? row)
    {
        if (row is not null)
        {
            StatusText = await _actions
                .BlockAsync(row.AppDisplayName, row.PathText, FirewallDirection.Inbound)
                .ConfigureAwait(true);
            _actionStatusUntilUtc = DateTime.UtcNow + ActionStatusHold;
        }
    }

    [RelayCommand]
    private async Task EndTaskAsync(ConnectionRow? row)
    {
        if (row is not null)
        {
            StatusText = await _actions
                .EndTaskAsync(row.AppDisplayName, [row.ProcessId])
                .ConfigureAwait(true);
            _actionStatusUntilUtc = DateTime.UtcNow + ActionStatusHold;
        }
    }

    private async Task CopyAsync(ConnectionRow? row, string? value)
    {
        if (row is null || string.IsNullOrWhiteSpace(value) || value == "—")
        {
            return;
        }

        try
        {
            await _ui.CopyTextAsync(value, CancellationToken.None).ConfigureAwait(true);
            StatusText = "Copied to the clipboard.";
            _actionStatusUntilUtc = DateTime.UtcNow + ActionStatusHold;
        }
        catch (Exception exception) when (exception is
                     InvalidOperationException or NotSupportedException or System.Runtime.InteropServices.ExternalException)
        {
            StatusText = "Clipboard is unavailable.";
            _actionStatusUntilUtc = DateTime.UtcNow + ActionStatusHold;
        }
    }

    public void Activate()
    {
        _isActive = true;
        if (_dirty)
        {
            _dirty = false;
            RefreshFromMonitor();
        }
    }

    public void Deactivate() => _isActive = false;

    public void Dispose()
    {
        _monitor.Updated -= OnUpdated;
    }

    private void OnUpdated(object? sender, EventArgs e)
    {
        if (!_isActive)
        {
            _dirty = true;
            return;
        }

        RefreshFromMonitor();
    }

    private void RefreshFromMonitor()
    {
        ApplyFilters();
        if (_monitor.LastError is { } error)
        {
            var captured = _monitor.LastCaptureUtc is { } timestamp
                ? $" · last capture {timestamp.ToLocalTime():HH:mm:ss}"
                : string.Empty;
            StatusText = $"Unavailable: {error}{captured}";
            return;
        }

        if (DateTime.UtcNow >= _actionStatusUntilUtc)
        {
            StatusText = $"Live read-only · {_monitor.SourceName} · {_monitor.PollInterval.TotalSeconds:0} s";
        }
    }

    private void ApplyFilters()
    {
        var search = SearchText.Trim();
        var protocol = ProtocolFilter;

        var filtered = _monitor.Connections
            .Where(row =>
                (search.Length == 0 || row.SearchBlob.Contains(search, StringComparison.OrdinalIgnoreCase)) &&
                (protocol == "All" ||
                 string.Equals(row.ProtocolText, protocol, StringComparison.OrdinalIgnoreCase)) &&
                (!OnlyNew || row.IsNew) &&
                (!OnlyLoopback || row.IsLoopback))
            .ToList();

        _rebuilding = true;
        if (!VisibleConnections.SequenceEqual(filtered))
        {
            VisibleConnections.Clear();
            foreach (var row in filtered)
            {
                VisibleConnections.Add(row);
            }
        }

        var traffic = _monitor.AppTraffic.ToDictionary(
            item => item.Key,
            StringComparer.OrdinalIgnoreCase);
        var desired = SortGroups(
                VisibleConnections
                    .GroupBy(
                        row => row.Source.AppPath.Length > 0
                            ? row.Source.AppPath
                            : $"pid:{row.ProcessId}",
                        StringComparer.OrdinalIgnoreCase)
                    .Select(group =>
                    {
                        var rows = group.ToList();
                        traffic.TryGetValue(group.Key, out var totals);
                        var sent = totals?.BytesSent ?? rows.Sum(row => row.ObservedBytesSent ?? 0);
                        var received = totals?.BytesReceived ?? rows.Sum(row => row.ObservedBytesReceived ?? 0);
                        return new GroupSnapshot(
                            group.Key,
                            rows[0].AppDisplayName,
                            rows[0].Source.AppPath,
                            rows,
                            sent,
                            received,
                            totals?.SentBytesPerSecond ?? 0,
                            totals?.ReceivedBytesPerSecond ?? 0,
                            totals?.SinceUtc,
                            totals?.SinceUtc is not null ||
                            rows.Any(row => row.ObservedBytesSent is not null));
                    }))
            .ToList();

        SyncGroups(desired);

        if (_selectedKey is not null)
        {
            SelectedConnection = VisibleConnections.FirstOrDefault(row => SelectionKey(row) == _selectedKey);
        }

        _rebuilding = false;

        IsEmpty = VisibleConnections.Count == 0;
        VisibleRowsText = $"{VisibleConnections.Count} of {_monitor.Connections.Count} sockets";
        if (_monitor.LastError is null && DateTime.UtcNow >= _actionStatusUntilUtc)
        {
            StatusText = $"Live read-only · {_monitor.SourceName} · {VisibleRowsText}";
        }
    }

    private IEnumerable<GroupSnapshot> SortGroups(IEnumerable<GroupSnapshot> groups)
    {
        var ordered = GroupSort switch
        {
            "Sent" => GroupSortDescending
                ? groups.OrderByDescending(group => group.HasMeasurement).ThenByDescending(group => group.BytesSent)
                : groups.OrderByDescending(group => group.HasMeasurement).ThenBy(group => group.BytesSent),
            "Received" => GroupSortDescending
                ? groups.OrderByDescending(group => group.HasMeasurement).ThenByDescending(group => group.BytesReceived)
                : groups.OrderByDescending(group => group.HasMeasurement).ThenBy(group => group.BytesReceived),
            "Sockets" => GroupSortDescending
                ? groups.OrderByDescending(group => group.Rows.Count)
                : groups.OrderBy(group => group.Rows.Count),
            "Name" => GroupSortDescending
                ? groups.OrderByDescending(group => group.Name, StringComparer.OrdinalIgnoreCase)
                : groups.OrderBy(group => group.Name, StringComparer.OrdinalIgnoreCase),
            _ => GroupSortDescending
                ? groups.OrderByDescending(group => group.HasMeasurement).ThenByDescending(group => group.TotalBytes)
                : groups.OrderByDescending(group => group.HasMeasurement).ThenBy(group => group.TotalBytes),
        };

        return ordered.ThenBy(group => group.Name, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Keeps one <see cref="ConnectionAppGroup"/> instance per executable across refreshes, so an
    /// expanded group and its row list survive the one-second poll instead of being recreated.
    /// </summary>
    private void SyncGroups(IReadOnlyList<GroupSnapshot> desired)
    {
        var wanted = desired.Select(item => item.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        for (var index = Groups.Count - 1; index >= 0; index--)
        {
            var existing = Groups[index];
            if (!wanted.Contains(existing.Key))
            {
                _groupIndex.Remove(existing.Key);
                Groups.RemoveAt(index);
            }
        }

        for (var index = 0; index < desired.Count; index++)
        {
            var item = desired[index];
            if (!_groupIndex.TryGetValue(item.Key, out var group))
            {
                group = new ConnectionAppGroup(item.Key);
                _groupIndex[item.Key] = group;
                Groups.Insert(Math.Min(index, Groups.Count), group);
            }
            else
            {
                var current = Groups.IndexOf(group);
                if (current != index)
                {
                    Groups.Move(current, index);
                }
            }

            group.Update(
                item.Name,
                item.Path,
                item.Rows,
                item.BytesSent,
                item.BytesReceived,
                item.SentBytesPerSecond,
                item.ReceivedBytesPerSecond,
                item.SinceUtc);
        }
    }

    private sealed record GroupSnapshot(
        string Key,
        string Name,
        string Path,
        IReadOnlyList<ConnectionRow> Rows,
        long BytesSent,
        long BytesReceived,
        double SentBytesPerSecond,
        double ReceivedBytesPerSecond,
        DateTimeOffset? SinceUtc,
        bool HasMeasurement)
    {
        public long TotalBytes => BytesSent + BytesReceived;
    }
}
