// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Contracts.Firewall;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

public sealed partial class ConnectionsPageViewModel : PageViewModel, IDisposable
{
    private readonly ConnectionMonitor _monitor;
    private readonly IUserInteraction _ui;
    private readonly ConnectionActionService _actions;
    private string? _selectedKey;

    public ConnectionsPageViewModel(
        ConnectionMonitor monitor,
        IUserInteraction? ui = null,
        IServiceRequestClient? serviceClient = null,
        IProcessActions? processActions = null)
        : base("Connections", "Sockets read from this Windows host · read-only", "C")
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

    [ObservableProperty]
    private bool _isGroupedByApp;

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

    partial void OnSelectedConnectionChanged(ConnectionRow? value) => _selectedKey = value?.Source.RemoteEndpoint is { } remote
        ? $"{value.ProcessId}|{value.ProtocolText}|{value.LocalEndpoint}|{remote}"
        : null;

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
        }
        catch (Exception exception) when (exception is
                     InvalidOperationException or NotSupportedException or System.Runtime.InteropServices.ExternalException)
        {
            StatusText = "Clipboard is unavailable.";
        }
    }

    public void Dispose()
    {
        _monitor.Updated -= OnUpdated;
    }

    private void OnUpdated(object? sender, EventArgs e)
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

        StatusText = $"Live read-only · {_monitor.SourceName} · {_monitor.PollInterval.TotalSeconds:0} s";
    }

    private void ApplyFilters()
    {
        var search = SearchText.Trim();
        var protocol = ProtocolFilter;

        var filtered = _monitor.Connections.Where(row =>
            (search.Length == 0 || row.SearchBlob.Contains(search, StringComparison.OrdinalIgnoreCase)) &&
            (protocol == "All" ||
             string.Equals(row.ProtocolText, protocol, StringComparison.OrdinalIgnoreCase)) &&
            (!OnlyNew || row.IsNew) &&
            (!OnlyLoopback || row.IsLoopback));

        VisibleConnections.Clear();
        foreach (var row in filtered)
        {
            VisibleConnections.Add(row);
        }

        Groups.Clear();
        foreach (var group in VisibleConnections
                     .GroupBy(
                         row => row.PathText.Length > 0 ? row.PathText : row.AppDisplayName,
                         StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(group => group.Count())
                     .ThenBy(group => group.First().AppDisplayName, StringComparer.OrdinalIgnoreCase))
        {
            var rows = group.ToList();
            Groups.Add(new ConnectionAppGroup(
                group.Key,
                rows[0].AppDisplayName,
                rows[0].PathText,
                rows));
        }

        if (_selectedKey is not null)
        {
            SelectedConnection = VisibleConnections.FirstOrDefault(row =>
                $"{row.ProcessId}|{row.ProtocolText}|{row.LocalEndpoint}|{row.Source.RemoteEndpoint}" == _selectedKey);
        }

        IsEmpty = VisibleConnections.Count == 0;
        VisibleRowsText = $"{VisibleConnections.Count} of {_monitor.Connections.Count} sockets";
        if (_monitor.LastError is null)
        {
            StatusText = $"Live read-only · {_monitor.SourceName} · {VisibleRowsText}";
        }
    }
}
