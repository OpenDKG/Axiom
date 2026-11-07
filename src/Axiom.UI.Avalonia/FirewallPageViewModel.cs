// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Protection;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>One owned Windows Firewall rule, read-only.</summary>
public sealed class FirewallRuleRow(ManagedRule rule)
{
    public Guid ManagedRuleId => rule.ManagedRuleId;

    public string OsRuleName => rule.OsRuleName;

    public string Application => rule.Spec.AppPath.Length == 0
        ? "—"
        : Path.GetFileName(rule.Spec.AppPath);

    public string DirectionText => rule.Spec.Direction == FirewallDirection.Outbound ? "Out" : "In";

    public string ActionText => rule.Spec.Action == FirewallAction.Block ? "Block" : "Allow";

    public string ProfilesText => rule.Spec.Profiles switch
    {
        FirewallProfile.All => "Domain, Private, Public",
        FirewallProfile.None => "None",
        _ => string.Join(", ", new[]
        {
            rule.Spec.Profiles.HasFlag(FirewallProfile.Domain) ? "Domain" : null,
            rule.Spec.Profiles.HasFlag(FirewallProfile.Private) ? "Private" : null,
            rule.Spec.Profiles.HasFlag(FirewallProfile.Public) ? "Public" : null,
        }.Where(part => part is not null)),
    };

    public string ProtocolText => rule.Spec.Protocol switch
    {
        NetworkProtocol.Tcp => "TCP",
        NetworkProtocol.Udp => "UDP",
        _ => "Any",
    };

    public string PortsText => string.IsNullOrWhiteSpace(rule.Spec.RemotePorts) ? "any" : rule.Spec.RemotePorts;

    public string EnabledText => rule.Spec.Enabled ? "yes" : "no";

    public string StateText => rule.State.ToString();

    public string Tooltip =>
        $"{rule.Spec.AppPath}\nRule: {rule.OsRuleName}\nCreated by: {rule.Spec.CreatedBy}";
}

/// <summary>One outbound application that is waiting for a Block/Allow decision.</summary>
public sealed class PendingAppRow(ProtectionPendingApp app)
{
    public string AppPath => app.AppPath;

    public string AppName => app.AppName;

    public string SocketText => $"{app.SocketCount} socket(s)";

    public string FirstSeenText => app.FirstObservedUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    public bool IsAgent => app.IsAgent;

    public string AgentText => app.IsAgent ? "agent" : string.Empty;

    public string Tooltip => app.AppPath;
}

/// <summary>
/// Firewall page. It reads the capability and owned rules through the service. Apply/Remove stay
/// disabled unless the service opened its explicit write gate, and every change asks first.
/// </summary>
public sealed partial class FirewallPageViewModel : PageViewModel, IDisposable
{
    private readonly IServiceRequestClient? _client;
    private readonly IUserInteraction _ui;
    private readonly FirewallDefaultsStore _defaultsStore = FirewallDefaultsStore.Shared;

    public FirewallPageViewModel(IServiceRequestClient? serviceClient, IUserInteraction ui)
        : base("Firewall", "Owned rules, defaults and rule editor", "F")
    {
        ArgumentNullException.ThrowIfNull(ui);
        _client = serviceClient;
        _ui = ui;

        ApplyDefaults(_defaultsStore.Load());
        CopyDefaultsToNewRule();

        if (_client is null)
        {
            CapabilityStatusText = "Service required";
            CapabilityDetail = "Firewall policy is read through the local service. Start this host with --service.";
            OwnedRuleCountText = "—";
            StatusText = "No Windows Firewall policy was read in in-process mode.";
            IsEmpty = true;
            return;
        }

        CanRecheck = true;
        _ = RefreshAsync();
    }

    public ObservableCollection<FirewallRuleRow> Rules { get; } = [];

    public ObservableCollection<PendingAppRow> Pending { get; } = [];

    public IReadOnlyList<string> ProtocolOptions { get; } = ["Any", "TCP", "UDP"];

    public IReadOnlyList<string> DirectionOptions { get; } = ["Outbound", "Inbound"];

    public IReadOnlyList<string> ActionOptions { get; } = ["Block", "Allow"];

    [ObservableProperty]
    private bool _defaultDomain = true;

    [ObservableProperty]
    private bool _defaultPrivate = true;

    [ObservableProperty]
    private bool _defaultPublic = true;

    [ObservableProperty]
    private string _defaultProtocolText = "Any";

    [ObservableProperty]
    private string _defaultPortsText = string.Empty;

    [ObservableProperty]
    private string _defaultAddressesText = string.Empty;

    [ObservableProperty]
    private string _defaultsStatusText = "Defaults apply to new block rules created from Applications.";

    [ObservableProperty]
    private string _newRulePath = string.Empty;

    [ObservableProperty]
    private string _newRuleDirectionText = "Outbound";

    [ObservableProperty]
    private string _newRuleActionText = "Block";

    [ObservableProperty]
    private bool _newRuleDomain = true;

    [ObservableProperty]
    private bool _newRulePrivate = true;

    [ObservableProperty]
    private bool _newRulePublic = true;

    [ObservableProperty]
    private string _newRuleProtocolText = "Any";

    [ObservableProperty]
    private string _newRulePortsText = string.Empty;

    [ObservableProperty]
    private string _newRuleAddressesText = string.Empty;

    [ObservableProperty]
    private bool _newRuleEnabled = true;

    [ObservableProperty]
    private string _newRuleStatusText = "Writes are disabled; the rule editor is read-only until the test-VM write gate is enabled.";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ApplyNewRuleCommand))]
    private bool _isApplyingRule;

    [ObservableProperty]
    private string _capabilityStatusText = "Checking…";

    [ObservableProperty]
    private string _capabilityDetail = string.Empty;

    [ObservableProperty]
    private string _ownedRuleCountText = "—";

    [ObservableProperty]
    private string _statusText = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RemoveRuleCommand))]
    [NotifyCanExecuteChangedFor(nameof(ApplyNewRuleCommand))]
    private bool _isBusy;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RemoveRuleCommand))]
    [NotifyCanExecuteChangedFor(nameof(ApplyNewRuleCommand))]
    [NotifyPropertyChangedFor(nameof(NoticeText))]
    [NotifyPropertyChangedFor(nameof(NoticeBadgeText))]
    [NotifyPropertyChangedFor(nameof(NewRuleWriteHint))]
    private bool _writesEnabled;

    public string NoticeText => WritesEnabled
        ? "Axiom Shield is on. Rules are read and written through the elevated local service with the documented INetFwPolicy2 COM objects. Every change is confirmed and audited."
        : "This session is read-only for Windows Firewall changes. Turn on Axiom Shield to let the elevated service create Axiom-owned rules. Until then only inventory, defaults and the rule editor are available.";

    public string NoticeBadgeText => WritesEnabled ? "SHIELD ON" : "READ-ONLY";

    public string NewRuleWriteHint => WritesEnabled
        ? "Axiom Shield is on. Each change is confirmed and audited; only Axiom-owned rules are touched."
        : "Turn on Axiom Shield to enable writes. Without it the rule editor stays read-only.";

    [ObservableProperty]
    private string _writePathText = "disabled";

    [ObservableProperty]
    private bool _isEmpty;

    [ObservableProperty]
    private bool _hasError;

    [ObservableProperty]
    private bool _canRecheck;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ToggleShieldCommand))]
    [NotifyCanExecuteChangedFor(nameof(BlockPendingCommand))]
    [NotifyCanExecuteChangedFor(nameof(AllowPendingCommand))]
    [NotifyCanExecuteChangedFor(nameof(ToggleAgentLockdownCommand))]
    private bool _isShieldBusy;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ToggleAgentLockdownCommand))]
    [NotifyPropertyChangedFor(nameof(ShieldBadgeText))]
    [NotifyPropertyChangedFor(nameof(ShieldActionText))]
    private bool _shieldEnabled;

    [ObservableProperty]
    private bool _shieldAvailable;

    [ObservableProperty]
    private bool _serviceElevated;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ToggleAgentLockdownCommand))]
    [NotifyPropertyChangedFor(nameof(AgentLockdownActionText))]
    private bool _agentLockdown;

    [ObservableProperty]
    private string _shieldStatusText = "Checking the local service…";

    [ObservableProperty]
    private string _shieldHintText =
        "Axiom Shield applies Windows Firewall rules owned by Axiom. Nothing is blocked until you turn it on.";

    [ObservableProperty]
    private string _serviceAccountText = "unknown";

    [ObservableProperty]
    private int _pendingCount;

    [ObservableProperty]
    private bool _hasPending;

    [ObservableProperty]
    private int _agentPathCount;

    [ObservableProperty]
    private string _agentLockdownHintText = "No agent executable is connected right now.";

    public string ShieldBadgeText => ShieldEnabled ? "ON" : "OFF";

    public string ShieldActionText => ShieldEnabled ? "Disable protection" : "Enable protection";

    public string AgentLockdownActionText => AgentLockdown ? "Remove agent lockdown" : "Lock agents to localhost";

    public void Dispose()
    {
    }

    [RelayCommand]
    private void SaveDefaults()
    {
        var profiles = BuildProfiles(DefaultDomain, DefaultPrivate, DefaultPublic);
        if (profiles == FirewallProfile.None)
        {
            DefaultsStatusText = "Select at least one profile for the defaults.";
            return;
        }

        var defaults = new FirewallDefaults(
            profiles,
            ParseProtocol(DefaultProtocolText),
            DefaultPortsText.Trim(),
            DefaultAddressesText.Trim());

        DefaultsStatusText = _defaultsStore.Save(defaults)
            ? "Defaults saved. New rules created from Applications will use this scope."
            : "Defaults could not be saved. Check the per-user data folder.";
        CopyDefaultsToNewRule();
    }

    [RelayCommand]
    private void ResetDefaults()
    {
        ApplyDefaults(FirewallDefaults.Default);
        CopyDefaultsToNewRule();
        DefaultsStatusText = "Defaults reset to all profiles, any protocol and any address.";
    }

    [RelayCommand]
    private async Task BrowseNewRuleExecutableAsync()
    {
        var path = await _ui
            .PickOpenFileAsync("Select an executable for the Axiom firewall rule", ".exe", "Executables", CancellationToken.None)
            .ConfigureAwait(true);
        if (path is not null)
        {
            NewRulePath = path;
        }
    }

    private bool CanApplyNewRule() => WritesEnabled && !IsBusy && !IsApplyingRule;

    [RelayCommand(CanExecute = nameof(CanApplyNewRule))]
    private async Task ApplyNewRuleAsync()
    {
        if (_client is null)
        {
            NewRuleStatusText = "Firewall writes require the local service.";
            return;
        }

        var path = NewRulePath.Trim();
        if (path.Length == 0 || !Path.IsPathFullyQualified(path))
        {
            NewRuleStatusText = "Select an absolute executable path first.";
            return;
        }

        var profiles = BuildProfiles(NewRuleDomain, NewRulePrivate, NewRulePublic);
        if (profiles == FirewallProfile.None)
        {
            NewRuleStatusText = "Select at least one network profile.";
            return;
        }

        var direction = string.Equals(NewRuleDirectionText, "Inbound", StringComparison.OrdinalIgnoreCase)
            ? FirewallDirection.Inbound
            : FirewallDirection.Outbound;
        var action = string.Equals(NewRuleActionText, "Allow", StringComparison.OrdinalIgnoreCase)
            ? FirewallAction.Allow
            : FirewallAction.Block;
        var addresses = NewRuleAddressesText.Split(
            [',', ';', ' '],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var spec = new RuleSpec
        {
            ManagedRuleId = RuleIdentity.ForApp(path, direction),
            AppPath = path,
            Direction = direction,
            Action = action,
            Profiles = profiles,
            Protocol = ParseProtocol(NewRuleProtocolText),
            RemoteAddresses = addresses,
            RemotePorts = string.IsNullOrWhiteSpace(NewRulePortsText) ? null : NewRulePortsText.Trim(),
            Enabled = NewRuleEnabled,
            CreatedBy = Environment.UserName,
            Description = $"Axiom {action.ToString().ToLowerInvariant()} for {Path.GetFileName(path)}",
        };

        var confirmed = await _ui.ConfirmAsync(
            "Axiom firewall write",
            $"Create or update the Axiom-owned {action.ToString().ToLowerInvariant()} rule for:\n{path}\n\n" +
            "Only this rule is changed. Other Windows Firewall rules are not touched. Continue only on an isolated test VM.",
            "Apply rule",
            destructive: true,
            CancellationToken.None).ConfigureAwait(true);

        if (!confirmed)
        {
            NewRuleStatusText = "Rule change cancelled.";
            return;
        }

        IsApplyingRule = true;
        try
        {
            var result = await _client
                .SendAsync<RuleApplyResult>(IpcCommandTypes.RuleApply, spec, CancellationToken.None)
                .ConfigureAwait(true);

            NewRuleStatusText = result.Success
                ? $"Rule applied and verified at {result.VerifiedUtc?.ToString("HH:mm:ss", CultureInfo.InvariantCulture) ?? "unknown"}."
                : $"Rule apply failed: {result.ErrorCode} - {result.ErrorMessage}";

            if (result.Success)
            {
                await RefreshAsync().ConfigureAwait(true);
            }
        }
        catch (ServiceUnavailableException exception)
        {
            NewRuleStatusText = exception.Message;
        }
#pragma warning disable CA1031 // The UI must show an IPC failure instead of crashing.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            NewRuleStatusText = $"Rule apply failed: {exception.Message}";
        }
        finally
        {
            IsApplyingRule = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanRemoveRule))]
    private async Task RemoveRuleAsync(FirewallRuleRow? row)
    {
        if (_client is null || row is null || !WritesEnabled)
        {
            return;
        }

        var confirmed = await _ui.ConfirmAsync(
            "Axiom firewall write",
            $"Remove the owned Windows Firewall rule for {row.Application}?\n\n" +
            "Only this Axiom rule is removed; other Windows Firewall rules are not touched.",
            "Remove rule",
            destructive: true,
            CancellationToken.None).ConfigureAwait(true);

        if (!confirmed)
        {
            return;
        }

        try
        {
            var result = await _client
                .SendAsync<RuleApplyResult>(
                    IpcCommandTypes.RuleRemove,
                    new RuleReference { ManagedRuleId = row.ManagedRuleId },
                    CancellationToken.None)
                .ConfigureAwait(true);

            StatusText = result.Success
                ? $"Removed {row.OsRuleName}."
                : $"Remove failed: {result.ErrorCode} — {result.ErrorMessage}";

            if (result.Success)
            {
                await RefreshAsync().ConfigureAwait(true);
            }
        }
        catch (ServiceUnavailableException exception)
        {
            StatusText = exception.Message;
        }
#pragma warning disable CA1031 // The UI must show an IPC failure instead of crashing.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            StatusText = $"Remove failed: {exception.Message}";
        }
    }

    private bool CanRemoveRule() => WritesEnabled && !IsBusy;

    private bool CanToggleShield() => _client is not null && !IsShieldBusy;

    [RelayCommand(CanExecute = nameof(CanToggleShield))]
    private async Task ToggleShieldAsync()
    {
        if (_client is null)
        {
            ShieldStatusText = "Axiom Shield needs the local service.";
            return;
        }

        if (ShieldEnabled)
        {
            var confirmed = await _ui.ConfirmAsync(
                "Disable Axiom Shield",
                "Turn protection off and remove every Axiom-owned Windows Firewall rule?\n\n" +
                "Other firewall rules are not touched. Rules are re-created from your decisions when you enable it again.",
                "Disable protection",
                destructive: true,
                CancellationToken.None).ConfigureAwait(true);

            if (!confirmed)
            {
                return;
            }

            IsShieldBusy = true;
            try
            {
                var disabled = await _client
                    .SendAsync<ProtectionStatus>(IpcCommandTypes.ProtectionDisable, null, CancellationToken.None)
                    .ConfigureAwait(true);
                ApplyStatus(disabled);
                await RefreshAsync().ConfigureAwait(true);
            }
            catch (ServiceUnavailableException exception)
            {
                ShieldStatusText = exception.Message;
            }
#pragma warning disable CA1031 // The page must show an IPC failure instead of crashing.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                ShieldStatusText = $"Disable failed: {exception.Message}";
            }
            finally
            {
                IsShieldBusy = false;
            }

            return;
        }

        if (!ServiceElevated)
        {
            var approved = await _ui.ConfirmAsync(
                "Enable Axiom Shield",
                "Axiom installs and starts its Windows service so it can create machine-wide firewall rules.\n\n" +
                "Windows will ask for administrator approval once. The desktop app itself stays unprivileged.",
                "Continue",
                destructive: false,
                CancellationToken.None).ConfigureAwait(true);

            if (!approved)
            {
                ShieldStatusText = "Enable cancelled.";
                return;
            }

            IsShieldBusy = true;
            ShieldStatusText = "Waiting for the administrator prompt…";
            try
            {
                var install = ProtectionServiceInstall.InstallAndStart();
                if (!install.Success)
                {
                    ShieldStatusText = install.Message;
                    return;
                }

                ProtectionServiceInstall.StopInteractiveServiceProcesses();
                await WaitForElevatedServiceAsync().ConfigureAwait(true);
            }
            finally
            {
                IsShieldBusy = false;
            }
        }

        IsShieldBusy = true;
        try
        {
            var status = await _client
                .SendAsync<ProtectionStatus>(
                    IpcCommandTypes.ProtectionEnable,
                    new ProtectionEnableRequest(),
                    CancellationToken.None)
                .ConfigureAwait(true);

            ApplyStatus(status);
            await RefreshAsync().ConfigureAwait(true);
        }
        catch (ServiceUnavailableException exception)
        {
            ShieldStatusText = exception.Message;
        }
#pragma warning disable CA1031 // The page must show an IPC failure instead of crashing.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            ShieldStatusText = $"Enable failed: {exception.Message}";
        }
        finally
        {
            IsShieldBusy = false;
        }
    }

    private bool CanDecidePending() => _client is not null && !IsShieldBusy && ShieldEnabled;

    [RelayCommand(CanExecute = nameof(CanDecidePending))]
    private Task BlockPendingAsync(PendingAppRow? row) =>
        DecidePendingAsync(row, ProtectionDecisionAction.Block);

    [RelayCommand(CanExecute = nameof(CanDecidePending))]
    private Task AllowPendingAsync(PendingAppRow? row) =>
        DecidePendingAsync(row, ProtectionDecisionAction.Allow);

    private async Task DecidePendingAsync(PendingAppRow? row, ProtectionDecisionAction action)
    {
        if (_client is null || row is null)
        {
            return;
        }

        if (action == ProtectionDecisionAction.Block)
        {
            var confirmed = await _ui.ConfirmAsync(
                "Block this application",
                $"Create a Windows Firewall block rule for:\n{row.AppPath}\n\n" +
                "Only the Axiom-owned rule is changed. You can remove it from the rules list at any time.",
                "Block",
                destructive: true,
                CancellationToken.None).ConfigureAwait(true);

            if (!confirmed)
            {
                return;
            }
        }

        IsShieldBusy = true;
        StatusText = $"{row.AppName}: applying {action.ToString().ToLowerInvariant()}…";
        try
        {
            var status = await _client
                .SendAsync<ProtectionStatus>(
                    IpcCommandTypes.ProtectionDecide,
                    new ProtectionDecideRequest
                    {
                        AppPath = row.AppPath,
                        AppName = row.AppName,
                        Action = action,
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            ApplyStatus(status);
            StatusText = status.LastError
                ?? $"{row.AppName}: {(action == ProtectionDecisionAction.Block ? "blocked" : "allowed")}.";
            await RefreshAsync().ConfigureAwait(true);
        }
        catch (ServiceUnavailableException exception)
        {
            StatusText = exception.Message;
        }
#pragma warning disable CA1031 // The page must show an IPC failure instead of crashing.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            StatusText = $"Decision failed: {exception.Message}";
        }
        finally
        {
            IsShieldBusy = false;
        }
    }

    private bool CanToggleAgentLockdown() => _client is not null && !IsShieldBusy && ShieldEnabled;

    [RelayCommand(CanExecute = nameof(CanToggleAgentLockdown))]
    private async Task ToggleAgentLockdownAsync()
    {
        if (_client is null)
        {
            return;
        }

        var enabling = !AgentLockdown;
        if (enabling)
        {
            var confirmed = await _ui.ConfirmAsync(
                "Lock agents to localhost",
                "Block internet access for every detected agent executable (OpenCode, Codex, Claude and similar).\n\n" +
                "Loopback traffic stays reachable, so the local Blackbox guard keeps working. Each agent gets its own Axiom block rule with a non-loopback address scope.",
                "Lock agents",
                destructive: true,
                CancellationToken.None).ConfigureAwait(true);

            if (!confirmed)
            {
                return;
            }
        }

        IsShieldBusy = true;
        try
        {
            var status = await _client
                .SendAsync<ProtectionStatus>(
                    IpcCommandTypes.ProtectionLockdown,
                    new ProtectionLockdownRequest { Enabled = enabling },
                    CancellationToken.None)
                .ConfigureAwait(true);

            ApplyStatus(status);
            StatusText = status.LastError
                ?? (enabling ? "Agent lockdown applied." : "Agent lockdown removed.");
            await RefreshAsync().ConfigureAwait(true);
        }
        catch (ServiceUnavailableException exception)
        {
            StatusText = exception.Message;
        }
#pragma warning disable CA1031 // The page must show an IPC failure instead of crashing.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            StatusText = $"Agent lockdown failed: {exception.Message}";
        }
        finally
        {
            IsShieldBusy = false;
        }
    }

    private async Task RefreshShieldAsync()
    {
        if (_client is null)
        {
            ShieldAvailable = false;
            ShieldStatusText = "Firewall policy needs the local service.";
            return;
        }

        try
        {
            var status = await _client
                .SendAsync<ProtectionStatus>(IpcCommandTypes.ProtectionStatus, null, CancellationToken.None)
                .ConfigureAwait(true);
            ApplyStatus(status);
        }
        catch (ServiceUnavailableException exception)
        {
            ShieldAvailable = false;
            ShieldStatusText = exception.Message;
        }
#pragma warning disable CA1031 // An older service build simply does not expose the shield yet.
        catch (Exception)
#pragma warning restore CA1031
        {
            ShieldAvailable = false;
            ShieldStatusText = "This service build does not expose Axiom Shield.";
        }
    }

    private async Task WaitForElevatedServiceAsync()
    {
        for (var attempt = 0; attempt < 30; attempt++)
        {
            await Task.Delay(TimeSpan.FromSeconds(1)).ConfigureAwait(true);
            try
            {
                var status = await _client!
                    .SendAsync<ProtectionStatus>(IpcCommandTypes.ProtectionStatus, null, CancellationToken.None)
                    .ConfigureAwait(true);

                if (status.ServiceElevated)
                {
                    ApplyStatus(status);
                    return;
                }
            }
            catch (ServiceUnavailableException)
            {
                // The service is restarting after installation; keep waiting.
            }
        }

        ShieldStatusText = "The Axiom service did not come up. Check Windows Services for 'Axiom'.";
    }

    private void ApplyStatus(ProtectionStatus status)
    {
        ShieldAvailable = true;
        ShieldEnabled = status.Enabled;
        ServiceElevated = status.ServiceElevated;
        AgentLockdown = status.AgentLockdown;
        ServiceAccountText = status.AccountName;
        WritesEnabled = status.WriteGateOpen;
        WritePathText = status.WriteGateOpen ? "enabled (Axiom Shield)" : "read-only";

        Pending.Clear();
        foreach (var app in status.Pending)
        {
            Pending.Add(new PendingAppRow(app));
        }

        PendingCount = status.Pending.Count;
        HasPending = PendingCount > 0;
        AgentPathCount = status.AgentPaths.Count;
        AgentLockdownHintText = AgentPathCount == 0
            ? "No agent executable is connected right now."
            : $"{AgentPathCount} agent executable(s) detected. Lockdown blocks internet access and keeps localhost reachable.";

        ShieldStatusText = !string.IsNullOrWhiteSpace(status.LastError)
            ? status.LastError!
            : status.Enabled
                ? $"Protection is on · {status.OwnedRuleCount} Axiom rule(s) · {status.Pending.Count} application(s) waiting for a decision."
                : "Protection is off. Axiom only observes.";

        ShieldHintText = !status.ServiceElevated
            ? "Enable installs the Axiom Windows service (one administrator approval). Until then Axiom can read rules but cannot enforce them."
            : status.Enabled
                ? "Ask policy: a new outbound application waits above until you choose Block or Allow. Every block is a Windows Firewall rule named Axiom::…."
                : "The service runs elevated and can enforce. Turn protection on to start the ask policy.";
    }

    private static FirewallProfile BuildProfiles(bool domain, bool privateProfile, bool publicProfile)
    {
        var profiles = FirewallProfile.None;
        if (domain)
        {
            profiles |= FirewallProfile.Domain;
        }

        if (privateProfile)
        {
            profiles |= FirewallProfile.Private;
        }

        if (publicProfile)
        {
            profiles |= FirewallProfile.Public;
        }

        return profiles;
    }

    private static NetworkProtocol ParseProtocol(string value) => value switch
    {
        "TCP" => NetworkProtocol.Tcp,
        "UDP" => NetworkProtocol.Udp,
        _ => NetworkProtocol.Any,
    };

    private void ApplyDefaults(FirewallDefaults defaults)
    {
        DefaultDomain = defaults.Profiles.HasFlag(FirewallProfile.Domain);
        DefaultPrivate = defaults.Profiles.HasFlag(FirewallProfile.Private);
        DefaultPublic = defaults.Profiles.HasFlag(FirewallProfile.Public);
        DefaultProtocolText = defaults.Protocol switch
        {
            NetworkProtocol.Tcp => "TCP",
            NetworkProtocol.Udp => "UDP",
            _ => "Any",
        };
        DefaultPortsText = defaults.RemotePorts;
        DefaultAddressesText = defaults.RemoteAddresses;
    }

    private void CopyDefaultsToNewRule()
    {
        NewRuleDomain = DefaultDomain;
        NewRulePrivate = DefaultPrivate;
        NewRulePublic = DefaultPublic;
        NewRuleProtocolText = DefaultProtocolText;
        NewRulePortsText = DefaultPortsText;
        NewRuleAddressesText = DefaultAddressesText;
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        if (_client is null || IsBusy)
        {
            return;
        }

        IsBusy = true;

        try
        {
            var snapshot = await _client
                .SendAsync<FirewallRulesSnapshot>(IpcCommandTypes.RulesQuery, null, CancellationToken.None)
                .ConfigureAwait(true);

            Rules.Clear();
            foreach (var rule in snapshot.Rules)
            {
                Rules.Add(new FirewallRuleRow(rule));
            }

            CapabilityStatusText = snapshot.Capability.Status switch
            {
                FirewallCapabilityStatus.Available => "Available",
                FirewallCapabilityStatus.Degraded => "Degraded",
                FirewallCapabilityStatus.Unavailable => "Unavailable",
                _ => "Unknown",
            };
            CapabilityDetail = snapshot.Capability.Reason
                ?? "Windows Firewall COM policy is readable. No rule is changed by this page.";
            OwnedRuleCountText = snapshot.Rules.Count.ToString(CultureInfo.InvariantCulture);
            IsEmpty = snapshot.Rules.Count == 0;
            WritesEnabled = snapshot.WritesEnabled;
            WritePathText = snapshot.WritesEnabled ? "enabled (test VM only)" : "disabled";
            HasError = snapshot.Capability.Status == FirewallCapabilityStatus.Unavailable;
            StatusText = snapshot.Rules.Count == 0
                ? "0 owned rules. Axiom has not created any Windows Firewall rule on this host."
                : $"{snapshot.Rules.Count} owned rules read at {DateTimeOffset.Now:HH:mm:ss}.";

            await RefreshShieldAsync().ConfigureAwait(true);
        }
        catch (ServiceUnavailableException exception)
        {
            Rules.Clear();
            CapabilityStatusText = "Service offline";
            CapabilityDetail = exception.Message;
            OwnedRuleCountText = "—";
            IsEmpty = true;
            HasError = true;
            StatusText = exception.Message;
        }
#pragma warning disable CA1031 // The page must not stay busy on an unexpected IPC error.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            Rules.Clear();
            CapabilityStatusText = "Query failed";
            CapabilityDetail = exception.Message;
            OwnedRuleCountText = "—";
            IsEmpty = true;
            HasError = true;
            StatusText = $"Firewall query failed: {exception.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
