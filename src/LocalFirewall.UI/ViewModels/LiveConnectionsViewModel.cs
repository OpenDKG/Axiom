// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LocalFirewall.Contracts.Monitoring;
using LocalFirewall.UI.Services;

namespace LocalFirewall.UI.ViewModels;

public sealed partial class LiveConnectionsViewModel : PageViewModel, IDisposable
{
    private const string AllProtocols = "All";

    private readonly ConnectionMonitor _monitor;

    private readonly CollectionView _view;

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

    public void Dispose() => _monitor.Updated -= OnMonitorUpdated;

    partial void OnProtocolFilterChanged(string value) => ApplyFilter();

    partial void OnSearchTextChanged(string value) => ApplyFilter();

    partial void OnOnlyNewChanged(bool value) => ApplyFilter();

    partial void OnOnlyLoopbackChanged(bool value) => ApplyFilter();

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
