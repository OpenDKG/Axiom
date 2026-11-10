// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Executables observed in the live socket inventory. Reads are always available from the monitor;
/// firewall writes require the service write gate and one explicit confirmation per rule.
/// </summary>
public sealed partial class AppsPageViewModel : PageViewModel, IDisposable
{
    private const double MaxBarWidth = 190;

    private readonly ConnectionMonitor _monitor;
    private readonly Dictionary<string, AppRow> _rows = new(StringComparer.OrdinalIgnoreCase);
    private readonly IServiceRequestClient? _client;
    private readonly IUserInteraction _ui;
    private readonly IProcessActions _processes;
    private readonly FirewallDefaultsStore _firewallDefaults = FirewallDefaultsStore.Shared;
    private string? _selectedKey;

    public AppsPageViewModel(
        ConnectionMonitor monitor,
        IServiceRequestClient? serviceClient,
        IUserInteraction ui,
        IProcessActions processes)
        : base("Applications", "Executables observed on this host · grouped by resolved path", "A")
    {
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));
        _client = serviceClient;
        _ui = ui ?? throw new ArgumentNullException(nameof(ui));
        _processes = processes ?? throw new ArgumentNullException(nameof(processes));

        if (_client is null)
        {
            WriteStatusText = "Firewall writes require the local service. Start this host with --service.";
        }
        else
        {
            _ = LoadWriteCapabilityAsync();
        }

        ApplyFirewallDefaults(_firewallDefaults.Load());
        _firewallDefaults.Changed += OnFirewallDefaultsChanged;
        monitor.Updated += OnMonitorUpdated;
        Rebuild();
    }

    public ObservableCollection<AppRow> Apps { get; } = [];

    [ObservableProperty]
    private AppRow? _selectedApp;

    [ObservableProperty]
    private bool _hasSelection;

    [ObservableProperty]
    private bool _canWrite;

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

    public string ModeBadgeText => _client is null ? "LIVE · READ-ONLY" : "LIVE · SERVICE";

    public IReadOnlyList<string> ProtocolOptions { get; } = ["Any", "TCP", "UDP"];

    public void Dispose()
    {
        _monitor.Updated -= OnMonitorUpdated;
        _firewallDefaults.Changed -= OnFirewallDefaultsChanged;
    }

    partial void OnSelectedAppChanged(AppRow? value)
    {
        _selectedKey = value?.Key;
        HasSelection = value is not null;
    }

    [RelayCommand]
    private Task BlockOutboundAsync() => BlockAsync(SelectedApp, FirewallDirection.Outbound);

    [RelayCommand]
    private Task BlockInboundAsync() => BlockAsync(SelectedApp, FirewallDirection.Inbound);

    [RelayCommand]
    private Task BlockOutboundAppAsync(AppRow? app) => BlockAsync(app, FirewallDirection.Outbound);

    [RelayCommand]
    private Task BlockInboundAppAsync(AppRow? app) => BlockAsync(app, FirewallDirection.Inbound);

    [RelayCommand]
    private async Task EndTaskAppAsync(AppRow? app)
    {
        if (app is null || app.ProcessIds.Count == 0)
        {
            WriteStatusText = "This application has no live PID to end.";
            return;
        }

        var confirmed = await _ui.ConfirmAsync(
            "End task",
            $"End {app.Name} (PID {string.Join(", ", app.ProcessIds)})?\n\nUnsaved work in that process will be lost.",
            "End task",
            destructive: true,
            CancellationToken.None).ConfigureAwait(true);

        if (!confirmed)
        {
            return;
        }

        var ended = _processes.EndProcesses(app.ProcessIds);
        WriteStatusText = $"Ended {ended} process(es) for {app.Name}.";
    }

    [RelayCommand]
    private async Task CopyPathAppAsync(AppRow? app)
    {
        if (app is null || !app.HasPath)
        {
            return;
        }

        try
        {
            await _ui.CopyTextAsync(app.Path, CancellationToken.None).ConfigureAwait(true);
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
            WriteStatusText = OperatingSystem.IsMacOS()
                ? (CanWrite
                    ? "Firewall rules are enabled (Axiom Shield is on). Blocks are enforced by the AxiomFilter network extension."
                    : "Firewall rules are off. Turn on Axiom Shield on the Firewall page to create block rules.")
                : CanWrite
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
        var confirmed = await _ui.ConfirmAsync(
            "Axiom firewall write",
            $"Create a {PlatformText.Firewall} block rule for {app.Name} ({directionText})?\n\n" +
            "The rule is owned by Axiom and can be removed from the Firewall page." +
            (OperatingSystem.IsMacOS() ? string.Empty : " Only continue on an isolated test VM."),
            "Create rule",
            destructive: true,
            CancellationToken.None).ConfigureAwait(true);

        if (!confirmed)
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

        SortRows();

        SelectedApp = _selectedKey is not null && _rows.TryGetValue(_selectedKey, out var selected)
            ? selected
            : Apps.FirstOrDefault();

        SummaryText =
            $"{Apps.Count} executables · {_monitor.Connections.Count} sockets · " +
            $"{AppGrouping.CountUnowned(_monitor.Connections)} unowned (PID 0) · " +
            $"poll {_monitor.PollInterval.TotalSeconds:0} s";
    }

    private void SortRows()
    {
        var ordered = Apps
            .OrderByDescending(row => row.SocketCount)
            .ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        for (var target = 0; target < ordered.Count; target++)
        {
            var current = Apps.IndexOf(ordered[target]);
            if (current != target)
            {
                Apps.Move(current, target);
            }
        }
    }
}
