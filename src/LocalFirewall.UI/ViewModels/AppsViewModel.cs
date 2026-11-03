// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using LocalFirewall.UI.Services;

namespace LocalFirewall.UI.ViewModels;

public sealed partial class AppsViewModel : PageViewModel, IDisposable
{
    private const double MaxBarWidth = 190;

    private readonly ConnectionMonitor _monitor;

    private readonly Dictionary<string, AppRow> _rows = new(StringComparer.OrdinalIgnoreCase);

    private readonly ListCollectionView _view;

    private string? _selectedKey;

    public AppsViewModel(ConnectionMonitor monitor)
        : base("Apps", "Executables observed on this host · grouped by resolved path", "\uE71D")
    {
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));

        _view = (ListCollectionView)CollectionViewSource.GetDefaultView(Apps);
        _view.IsLiveSorting = true;
        _view.LiveSortingProperties.Add(nameof(AppRow.SocketCount));
        _view.SortDescriptions.Add(new SortDescription(nameof(AppRow.SocketCount), ListSortDirection.Descending));
        _view.SortDescriptions.Add(new SortDescription(nameof(AppRow.Name), ListSortDirection.Ascending));

        monitor.Updated += OnMonitorUpdated;
        Rebuild();
    }

    public ObservableCollection<AppRow> Apps { get; } = [];

    public ICollectionView View => _view;

    [ObservableProperty]
    private AppRow? _selectedApp;

    [ObservableProperty]
    private string _summaryText = string.Empty;

    public void Dispose() => _monitor.Updated -= OnMonitorUpdated;

    partial void OnSelectedAppChanged(AppRow? value) => _selectedKey = value?.Key;

    private void OnMonitorUpdated(object? sender, EventArgs e) => Rebuild();

    private void Rebuild()
    {
        var groups = AppGrouping.Group(_monitor.Connections);
        var keys = groups.Select(group => group.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var key in _rows.Keys.Where(key => !keys.Contains(key)).ToList())
        {
            var removed = _rows[key];
            _rows.Remove(key);
            Apps.Remove(removed);
        }

        var largest = groups.Count == 0 ? 0 : groups.Max(group => group.SocketCount);

        foreach (var group in groups)
        {
            var barWidth = largest == 0 ? 0 : Math.Max(4, group.SocketCount / (double)largest * MaxBarWidth);

            if (_rows.TryGetValue(group.Key, out var row))
            {
                row.Update(group, barWidth);
            }
            else
            {
                var added = new AppRow(group, barWidth);
                _rows.Add(group.Key, added);
                Apps.Add(added);
            }
        }

        SelectedApp = _selectedKey is not null && _rows.TryGetValue(_selectedKey, out var selected)
            ? selected
            : Apps.FirstOrDefault();

        SummaryText =
            $"{Apps.Count} executables · {_monitor.Connections.Count} sockets · " +
            $"{AppGrouping.CountUnowned(_monitor.Connections)} unowned (PID 0) · " +
            $"poll {_monitor.PollInterval.TotalSeconds:0} s";
    }
}
