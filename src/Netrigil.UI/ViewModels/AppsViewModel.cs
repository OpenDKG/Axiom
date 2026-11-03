// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Netrigil.Contracts.Firewall;
using Netrigil.Contracts.Ipc;
using Netrigil.UI.Services;

namespace Netrigil.UI.ViewModels;

public sealed partial class AppsViewModel : PageViewModel, IDisposable
{
    private const double MaxBarWidth = 190;

    private readonly ConnectionMonitor _monitor;

    private readonly Dictionary<string, AppRow> _rows = new(StringComparer.OrdinalIgnoreCase);

    private readonly ListCollectionView _view;

    private string? _selectedKey;

    private readonly ServicePipeClient? _client;

    public AppsViewModel(ConnectionMonitor monitor, bool serviceMode)
        : base("Applications", "Executables observed on this host · grouped by resolved path", "\uE71D")
    {
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));

        _view = (ListCollectionView)CollectionViewSource.GetDefaultView(Apps);
        _view.IsLiveSorting = true;
        _view.LiveSortingProperties.Add(nameof(AppRow.SocketCount));
        _view.SortDescriptions.Add(new SortDescription(nameof(AppRow.SocketCount), ListSortDirection.Descending));
        _view.SortDescriptions.Add(new SortDescription(nameof(AppRow.Name), ListSortDirection.Ascending));

        if (serviceMode)
        {
            _client = new ServicePipeClient();
            _ = LoadWriteCapabilityAsync();
        }
        else
        {
            WriteStatusText = "Firewall writes require the local service. Start the app with --service.";
        }

        monitor.Updated += OnMonitorUpdated;
        Rebuild();
    }

    public ObservableCollection<AppRow> Apps { get; } = [];

    public ICollectionView View => _view;

    [ObservableProperty]
    private AppRow? _selectedApp;

    [ObservableProperty]
    private bool _canWrite;

    [ObservableProperty]
    private string _writeStatusText = "Firewall writes are disabled.";

    [ObservableProperty]
    private string _summaryText = string.Empty;

    public void Dispose() => _monitor.Updated -= OnMonitorUpdated;

    partial void OnSelectedAppChanged(AppRow? value) => _selectedKey = value?.Key;

    [RelayCommand]
    private Task BlockOutboundAsync() => BlockAsync(FirewallDirection.Outbound);

    [RelayCommand]
    private Task BlockInboundAsync() => BlockAsync(FirewallDirection.Inbound);

    private async Task LoadWriteCapabilityAsync()
    {
        if (_client is null)
        {
            return;
        }

        try
        {
            var capabilities = await _client
                .SendAsync<ServiceCapabilities>(IpcCommandTypes.Capabilities, null, CancellationToken.None)
                .ConfigureAwait(true);

            CanWrite = capabilities.FirewallWrites;
            WriteStatusText = CanWrite
                ? "Firewall writes are enabled for this service session. Use only on an isolated test VM."
                : "Firewall writes are disabled. Set the explicit write gate on an isolated VM.";
        }
        catch (ServiceUnavailableException exception)
        {
            CanWrite = false;
            WriteStatusText = exception.Message;
        }
    }

    private async Task BlockAsync(FirewallDirection direction)
    {
        if (_client is null || !CanWrite)
        {
            WriteStatusText = "Firewall writes are disabled for this service session.";
            return;
        }

        if (SelectedApp is null)
        {
            WriteStatusText = "Select an application first.";
            return;
        }

        if (SelectedApp.Path.Length == 0)
        {
            WriteStatusText = "The executable path is not readable; a path-bound rule cannot be created.";
            return;
        }

        var directionText = direction == FirewallDirection.Outbound ? "outbound" : "inbound";
        var confirmation = MessageBox.Show(
            $"Create a Windows Firewall block rule for {SelectedApp.Name} ({directionText})?\n\n" +
            "The rule is owned by Netrigil and can be removed from the Firewall page. " +
            "Only continue on an isolated test VM.",
            "Netrigil firewall write",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmation != MessageBoxResult.Yes)
        {
            WriteStatusText = "Block cancelled.";
            return;
        }

        var spec = new RuleSpec
        {
            ManagedRuleId = RuleIdentity.ForApp(SelectedApp.Path, direction),
            AppPath = SelectedApp.Path,
            Direction = direction,
            Action = FirewallAction.Block,
            Profiles = FirewallProfile.All,
            CreatedBy = Environment.UserName,
            Description = $"Netrigil block for {SelectedApp.Name} ({directionText})",
        };

        try
        {
            var result = await _client
                .SendAsync<RuleApplyResult>(IpcCommandTypes.RuleApply, spec, CancellationToken.None)
                .ConfigureAwait(true);

            WriteStatusText = result.Success
                ? $"Block applied for {SelectedApp.Name} ({directionText}); verified at {result.VerifiedUtc:HH:mm:ss}."
                : $"Block failed: {result.ErrorCode} — {result.ErrorMessage}";
        }
        catch (ServiceUnavailableException exception)
        {
            WriteStatusText = exception.Message;
        }
#pragma warning disable CA1031 // The UI must show an IPC failure instead of crashing.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            WriteStatusText = $"Block failed: {exception.Message}";
        }
    }

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
