// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Netpetra.Contracts.Firewall;
using Netpetra.Contracts.Ipc;
using Netpetra.UI.Services;

namespace Netpetra.UI.ViewModels;

public sealed partial class AppsViewModel : PageViewModel, IDisposable
{
    private const double MaxBarWidth = 190;

    private readonly ConnectionMonitor _monitor;

    private readonly Dictionary<string, AppRow> _rows = new(StringComparer.OrdinalIgnoreCase);

    private readonly ListCollectionView _view;

    private string? _selectedKey;

    private readonly ServicePipeClient? _client;

    private readonly FirewallDefaultsStore _firewallDefaults = FirewallDefaultsStore.Shared;

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

        ApplyFirewallDefaults(_firewallDefaults.Load());
        _firewallDefaults.Changed += OnFirewallDefaultsChanged;
        monitor.Updated += OnMonitorUpdated;
        Rebuild();
    }

    public ObservableCollection<AppRow> Apps { get; } = [];

    public ICollectionView View => _view;

    [ObservableProperty]
    private AppRow? _selectedApp;

    [ObservableProperty]
    private bool _canWrite;

    public string ModeBadgeText => _client is null ? "LIVE · READ-ONLY" : "LIVE · SERVICE";

    public IReadOnlyList<string> ProtocolOptions { get; } = ["Any", "TCP", "UDP"];

    [ObservableProperty]
    private string _selectedProtocolText = "Any";

    [ObservableProperty]
    private string _remotePortsText = string.Empty;

    [ObservableProperty]
    private string _remoteAddressesText = string.Empty;

    [ObservableProperty]
    private bool _blockDomain = true;

    [ObservableProperty]
    private bool _blockPrivate = true;

    [ObservableProperty]
    private bool _blockPublic = true;

    [ObservableProperty]
    private string _writeStatusText = "Firewall writes are disabled.";

    [ObservableProperty]
    private string _summaryText = string.Empty;

    public void Dispose()
    {
        _monitor.Updated -= OnMonitorUpdated;
        _firewallDefaults.Changed -= OnFirewallDefaultsChanged;
    }

    partial void OnSelectedAppChanged(AppRow? value) => _selectedKey = value?.Key;

    [RelayCommand]
    private Task BlockOutboundAsync() => BlockAsync(SelectedApp, FirewallDirection.Outbound);

    [RelayCommand]
    private Task BlockInboundAsync() => BlockAsync(SelectedApp, FirewallDirection.Inbound);

    [RelayCommand]
    private Task BlockOutboundAppAsync(AppRow? app) => BlockAsync(app, FirewallDirection.Outbound);

    [RelayCommand]
    private Task BlockInboundAppAsync(AppRow? app) => BlockAsync(app, FirewallDirection.Inbound);

    [RelayCommand]
    private void EndTaskApp(AppRow? app)
    {
        if (app is null || app.ProcessIds.Count == 0)
        {
            WriteStatusText = "This application has no live PID to end.";
            return;
        }

        var confirmation = MessageBox.Show(
            $"End {app.Name} (PID {string.Join(", ", app.ProcessIds)})?\n\nUnsaved work in that process will be lost.",
            "End task",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmation != MessageBoxResult.Yes)
        {
            return;
        }

        var ended = 0;
        foreach (var pid in app.ProcessIds)
        {
            try
            {
                using var process = Process.GetProcessById(pid);
                process.Kill(entireProcessTree: true);
                ended++;
            }
#pragma warning disable CA1031 // A protected or already-exited process must not crash the UI.
            catch (Exception)
#pragma warning restore CA1031
            {
            }
        }

        WriteStatusText = $"Ended {ended} process(es) for {app.Name}.";
    }

    [RelayCommand]
    private void CopyPathApp(AppRow? app)
    {
        if (app is null || !app.HasPath)
        {
            return;
        }

        try
        {
            Clipboard.SetText(app.Path);
            WriteStatusText = "Executable path copied.";
        }
#pragma warning disable CA1031 // Clipboard can be locked by another process.
        catch (Exception)
#pragma warning restore CA1031
        {
            WriteStatusText = "Could not copy the path.";
        }
    }

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

    private async Task BlockAsync(AppRow? app, FirewallDirection direction)
    {
        if (_client is null || !CanWrite)
        {
            WriteStatusText = "Firewall writes are disabled for this service session.";
            return;
        }

        if (app is null)
        {
            WriteStatusText = "Select an application first.";
            return;
        }

        if (app.Path.Length == 0)
        {
            WriteStatusText = "The executable path is not readable; a path-bound rule cannot be created.";
            return;
        }

        var directionText = direction == FirewallDirection.Outbound ? "outbound" : "inbound";
        var confirmation = MessageBox.Show(
            $"Create a Windows Firewall block rule for {app.Name} ({directionText})?\n\n" +
            "The rule is owned by Axiom and can be removed from the Firewall page. " +
            "Only continue on an isolated test VM.",
            "Axiom firewall write",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmation != MessageBoxResult.Yes)
        {
            WriteStatusText = "Block cancelled.";
            return;
        }

        var spec = BuildSpec(app, direction);
        if (spec is null)
        {
            return;
        }

        try
        {
            var result = await _client
                .SendAsync<RuleApplyResult>(IpcCommandTypes.RuleApply, spec, CancellationToken.None)
                .ConfigureAwait(true);

            WriteStatusText = result.Success
                ? $"Block applied for {app.Name} ({directionText}); verified at {result.VerifiedUtc:HH:mm:ss}."
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

    private RuleSpec? BuildSpec(AppRow? app, FirewallDirection direction)
    {
        var profiles = FirewallProfile.None;

        if (BlockDomain)
        {
            profiles |= FirewallProfile.Domain;
        }

        if (BlockPrivate)
        {
            profiles |= FirewallProfile.Private;
        }

        if (BlockPublic)
        {
            profiles |= FirewallProfile.Public;
        }

        if (profiles == FirewallProfile.None)
        {
            WriteStatusText = "Select at least one network profile (Domain, Private or Public).";
            return null;
        }

        if (app is null)
        {
            return null;
        }

        var protocol = SelectedProtocolText switch
        {
            "TCP" => NetworkProtocol.Tcp,
            "UDP" => NetworkProtocol.Udp,
            _ => NetworkProtocol.Any,
        };

        var addresses = RemoteAddressesText.Split(
            [',', ';', ' '],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        return new RuleSpec
        {
            ManagedRuleId = RuleIdentity.ForApp(app.Path, direction),
            AppPath = app.Path,
            Direction = direction,
            Action = FirewallAction.Block,
            Profiles = profiles,
            Protocol = protocol,
            RemoteAddresses = addresses,
            RemotePorts = string.IsNullOrWhiteSpace(RemotePortsText) ? null : RemotePortsText.Trim(),
            CreatedBy = Environment.UserName,
            Description = $"Axiom block for {app.Name}",
        };
    }

    private void OnMonitorUpdated(object? sender, EventArgs e) => Rebuild();

    private void OnFirewallDefaultsChanged(object? sender, EventArgs e) =>
        ApplyFirewallDefaults(_firewallDefaults.Load());

    private void ApplyFirewallDefaults(FirewallDefaults defaults)
    {
        BlockDomain = defaults.Profiles.HasFlag(FirewallProfile.Domain);
        BlockPrivate = defaults.Profiles.HasFlag(FirewallProfile.Private);
        BlockPublic = defaults.Profiles.HasFlag(FirewallProfile.Public);
        SelectedProtocolText = defaults.Protocol switch
        {
            NetworkProtocol.Tcp => "TCP",
            NetworkProtocol.Udp => "UDP",
            _ => "Any",
        };
        RemotePortsText = defaults.RemotePorts;
        RemoteAddressesText = defaults.RemoteAddresses;
    }

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
