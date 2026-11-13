// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Avalonia.Threading;
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

    public string AppPath => rule.Spec.AppPath;

    public bool IsBlock => rule.Spec.Action == FirewallAction.Block;

    /// <summary>Agent lockdown rules are re-applied while lockdown stays on, so do not offer Unblock here.</summary>
    public bool IsAgentLockdownRule =>
        rule.Spec.Description?.Contains("agent lockdown", StringComparison.OrdinalIgnoreCase) == true;

    public bool CanUnblock => IsBlock && !IsAgentLockdownRule;
}

/// <summary>One remembered Shield decision, with the action that can reverse a block.</summary>
public sealed class ShieldDecisionRow(ProtectionDecision decision)
{
    public string AppPath => decision.AppPath;

    public string AppName => decision.AppName;

    public string ActionText => decision.Action == ProtectionDecisionAction.Block ? "Blocked" : "Allowed";

    public string DecidedText =>
        decision.DecidedUtc.ToLocalTime().ToString("MM-dd HH:mm", CultureInfo.InvariantCulture);

    public bool IsBlock => decision.Action == ProtectionDecisionAction.Block;

    public bool IsAgentLockdown => decision.IsAgentLockdown;

    public bool CanUnblock => IsBlock && !IsAgentLockdown;

    public bool CanBlock => !IsBlock && !IsAgentLockdown;

    public bool CanToggle => CanBlock || CanUnblock;

    public string ActionMenuText => IsBlock ? "Unblock" : "Block";

    public string ActionHint => IsBlock
        ? "Remove the Axiom block and record an allow decision."
        : "Create an Axiom outbound block rule for this application.";

    public string RuleText => decision.IsAgentLockdown
        ? "Agent lockdown"
        : decision.ManagedRuleId is null
            ? "No Axiom rule"
            : "Axiom rule";

    public string Tooltip =>
        $"{decision.AppPath}\nAction: {ActionText}\nDecided: {DecidedText}\n{RuleText}";
}

/// <summary>One outbound application that is waiting for a Block/Allow decision.</summary>
public sealed partial class PendingAppRow(ProtectionPendingApp app) : ObservableObject
{
    public string AppPath => app.AppPath;

    public string AppName => app.AppName;

    public string SocketText => $"{app.SocketCount} socket(s)";

    public string FirstSeenText => app.FirstObservedUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    public bool IsAgent => app.IsAgent;

    public string AgentText => app.IsAgent ? "agent" : string.Empty;

    public string Tooltip => app.AppPath;

    /// <summary>Remote endpoints for this pending executable, or a clear "not reported" phrase.</summary>
    public string RemoteSummary => app.RemoteEndpoints.Count == 0
        ? "an unreported remote endpoint"
        : string.Join(", ", app.RemoteEndpoints);

    public string RemoteText => app.RemoteEndpoints.Count == 0
        ? (app.IsConnected
            ? "Outbound connection · remote endpoint not reported"
            : "Connection ended · last remote endpoint not reported")
        : (app.IsConnected ? "Outbound → " : "Ended · last outbound → ") +
          string.Join(", ", app.RemoteEndpoints);

    public bool IsConnected => app.IsConnected;

    public string ConnectionText => app.IsConnected
        ? "connected"
        : app.LastSeenUtc is { } lastSeen
            ? $"ended · last seen {lastSeen.ToLocalTime():HH:mm:ss}"
            : "connection ended";

    public string TriggerText =>
        "Trigger: Axiom Shield ask policy. This executable opened a new outbound connection and has no Block/Allow decision yet. " +
        "It stays listed after the connection ends until you choose Block, Allow or Dismiss. " +
        "It is not a malware, VirusTotal or community-feed verdict. Block creates an outbound firewall rule; Allow records a decision.";

    /// <summary>True when an alert pointed at this application, so the row stands out.</summary>
    [ObservableProperty]
    private bool _isFocused;
}

/// <summary>
/// Firewall page. It reads the capability and owned rules through the service. Apply/Remove stay
/// disabled unless the service opened its explicit write gate, and every change asks first.
/// </summary>
public sealed partial class FirewallPageViewModel : PageViewModel, IDisposable, IActivatablePage
{
    private readonly IServiceRequestClient? _client;
    private readonly IUserInteraction _ui;
    private readonly ConnectionMonitor? _monitor;
    private readonly FirewallDefaultsStore _defaultsStore = FirewallDefaultsStore.Shared;

    public FirewallPageViewModel(IServiceRequestClient? serviceClient, IUserInteraction ui, ConnectionMonitor? monitor = null)
        : base("Network Control", "Axiom-owned firewall rules, defaults and rule editor", "F")
    {
        ArgumentNullException.ThrowIfNull(ui);
        _client = serviceClient;
        _ui = ui;
        _monitor = monitor;

        ApplyDefaults(_defaultsStore.Load());
        CopyDefaultsToNewRule();

        if (_client is null)
        {
            CapabilityStatusText = "Service required";
            CapabilityDetail = "Firewall policy is read through the local service. Start this host with --service.";
            OwnedRuleCountText = "—";
            StatusText = $"No {PlatformText.Firewall} policy was read in in-process mode.";
            IsEmpty = true;
            return;
        }

        CanRecheck = true;
        _ = RefreshAsync();
    }

    public ObservableCollection<FirewallRuleRow> Rules { get; } = [];

    public ObservableCollection<PendingAppRow> Pending { get; } = [];

    public ObservableCollection<ShieldDecisionRow> Decisions { get; } = [];

    [ObservableProperty]
    private bool _hasDecisions;

    [ObservableProperty]
    private int _decisionCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IgnoredMicrosoftText))]
    [NotifyPropertyChangedFor(nameof(HasIgnoredMicrosoft))]
    private int _ignoredMicrosoftCount;

    /// <summary>Explanation shown when Microsoft-signed processes were removed from the ask list.</summary>
    public string IgnoredMicrosoftText => IgnoredMicrosoftCount == 0
        ? string.Empty
        : OperatingSystem.IsWindows()
            ? $"{IgnoredMicrosoftCount} Microsoft-signed process(es) are not prompted."
            : $"{IgnoredMicrosoftCount} macOS system process(es) are not prompted.";

    public bool HasIgnoredMicrosoft => IgnoredMicrosoftCount > 0;

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

    /// <summary>
    /// What the OS filter reported about the published rules (macOS). Drives the "N rule(s) not
    /// enforced by the filter" block and the rejected-file / dropped-events banner.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RejectedRules))]
    [NotifyPropertyChangedFor(nameof(HasRejectedRules))]
    [NotifyPropertyChangedFor(nameof(RejectedRulesHeadline))]
    [NotifyPropertyChangedFor(nameof(HasFilterBanner))]
    [NotifyPropertyChangedFor(nameof(FilterBannerText))]
    [NotifyPropertyChangedFor(nameof(FilterEnforcedText))]
    [NotifyPropertyChangedFor(nameof(FilterConnectionText))]
    [NotifyPropertyChangedFor(nameof(HasFilterConnectionText))]
    private FilterEnforcementSummary _enforcement = FilterEnforcementSummary.None;

    public string FilterConnectionText => Enforcement.ConnectionText;

    public bool HasFilterConnectionText => Enforcement.HasConnectionText;

    public IReadOnlyList<RejectedRuleRow> RejectedRules => Enforcement.RejectedRules;

    public bool HasRejectedRules => Enforcement.HasRejectedRules;

    public string RejectedRulesHeadline => Enforcement.RejectedHeadline;

    public bool HasFilterBanner => Enforcement.HasBanner;

    public string FilterBannerText => Enforcement.BannerText;

    public string FilterEnforcedText => Enforcement.EnforcedText;

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
        ? OperatingSystem.IsWindows()
            ? "Axiom Shield is on. Rules are read and written through the elevated local service with the documented INetFwPolicy2 COM objects. Every change is confirmed and audited."
            : "Axiom Shield is on. Rules are written by the root axiomd service and enforced by the AxiomFilter network extension. Every change is confirmed and audited."
        : $"This session is read-only for {PlatformText.Firewall} changes. Turn on Axiom Shield to let the elevated service create Axiom-owned rules. Until then only inventory, defaults and the rule editor are available.";

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
    [NotifyCanExecuteChangedFor(nameof(DismissPendingCommand))]
    [NotifyCanExecuteChangedFor(nameof(BlockFocusedCommand))]
    [NotifyCanExecuteChangedFor(nameof(AllowFocusedCommand))]
    [NotifyCanExecuteChangedFor(nameof(DismissFocusedCommand))]
    [NotifyCanExecuteChangedFor(nameof(ToggleAgentLockdownCommand))]
    private bool _isShieldBusy;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ToggleAgentLockdownCommand))]
    [NotifyCanExecuteChangedFor(nameof(BlockPendingCommand))]
    [NotifyCanExecuteChangedFor(nameof(AllowPendingCommand))]
    [NotifyCanExecuteChangedFor(nameof(DismissPendingCommand))]
    [NotifyCanExecuteChangedFor(nameof(BlockFocusedCommand))]
    [NotifyCanExecuteChangedFor(nameof(AllowFocusedCommand))]
    [NotifyCanExecuteChangedFor(nameof(DismissFocusedCommand))]
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
        $"Axiom Shield applies {PlatformText.Firewall} rules owned by Axiom. Nothing is blocked until you turn it on.";

    [ObservableProperty]
    private string _serviceAccountText = "unknown";

    [ObservableProperty]
    private int _pendingCount;

    [ObservableProperty]
    private bool _hasPending;

    [ObservableProperty]
    private bool _hasAlertFocus;

    [ObservableProperty]
    private string _alertFocusText = string.Empty;

    private string[] _alertFocusPaths = [];

    [ObservableProperty]
    private bool _hasSingleFocusedPending;

    private PendingAppRow? _focusedPending;

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
            $"Only this rule is changed. Other {PlatformText.Firewall} rules are not touched." +
            (OperatingSystem.IsMacOS() ? string.Empty : " Continue only on an isolated test VM."),
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

            NewRuleStatusText = result.Success && result.State != RuleState.Pending
                ? $"Rule applied and verified at {result.VerifiedUtc?.ToString("HH:mm:ss", CultureInfo.InvariantCulture) ?? "unknown"}."
                : result.Success
                    ? RuleApplyResultText.Describe(result, "Rule")
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
            $"Remove the owned {PlatformText.Firewall} rule for {row.Application}?\n\n" +
            $"Only this Axiom rule is removed; other {PlatformText.Firewall} rules are not touched.",
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
                $"Turn protection off and remove every Axiom-owned {PlatformText.Firewall} rule?\n\n" +
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
                OperatingSystem.IsMacOS()
                    ? "Axiom installs and starts its background daemon (axiomd) so it can enforce firewall rules through the Axiom network filter.\n\n" +
                      "macOS will ask for an administrator password once. The desktop app itself stays unprivileged."
                    : $"Axiom installs and starts its {PlatformText.ServiceKind} so it can create machine-wide firewall rules.\n\n" +
                      $"{PlatformText.OsName} will ask for administrator approval once. The desktop app itself stays unprivileged.",
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
                var install = OperatingSystem.IsMacOS()
                    ? await ProtectionServiceInstall.InstallAndStartMacAsync(CancellationToken.None).ConfigureAwait(true)
                    : ProtectionServiceInstall.InstallAndStart();
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

    [RelayCommand(CanExecute = nameof(CanDecidePending))]
    private Task DismissPendingAsync(PendingAppRow? row) =>
        row is null ? Task.CompletedTask : DismissPendingCoreAsync(row);

    [RelayCommand(CanExecute = nameof(CanDecidePending))]
    private Task BlockFocusedAsync() =>
        _focusedPending is { } row ? DecidePendingAsync(row, ProtectionDecisionAction.Block) : Task.CompletedTask;

    [RelayCommand(CanExecute = nameof(CanDecidePending))]
    private Task AllowFocusedAsync() =>
        _focusedPending is { } row ? DecidePendingAsync(row, ProtectionDecisionAction.Allow) : Task.CompletedTask;

    [RelayCommand(CanExecute = nameof(CanDecidePending))]
    private Task DismissFocusedAsync() =>
        _focusedPending is { } row ? DismissPendingCoreAsync(row) : Task.CompletedTask;

    [RelayCommand(CanExecute = nameof(CanDecidePending))]
    private Task ToggleDecisionAsync(ShieldDecisionRow? row) =>
        row is { CanToggle: true }
            ? row.IsBlock
                ? ConfirmAndUnblockAsync(row.AppPath, row.AppName)
                : ConfirmAndBlockAsync(row.AppPath, row.AppName)
            : Task.CompletedTask;

    [RelayCommand(CanExecute = nameof(CanDecidePending))]
    private Task UnblockRuleAsync(FirewallRuleRow? row) =>
        row is { CanUnblock: true }
            ? ConfirmAndUnblockAsync(row.AppPath, row.Application)
            : Task.CompletedTask;

    [RelayCommand]
    private Task CopyPendingPathAsync(PendingAppRow? row) => CopyTextSafeAsync(row?.AppPath);

    [RelayCommand]
    private Task CopyPendingRemoteAsync(PendingAppRow? row) => CopyTextSafeAsync(row?.RemoteSummary);

    [RelayCommand]
    private Task CopyDecisionPathAsync(ShieldDecisionRow? row) => CopyTextSafeAsync(row?.AppPath);

    [RelayCommand]
    private Task CopyRulePathAsync(FirewallRuleRow? row) => CopyTextSafeAsync(row?.AppPath);

    [RelayCommand]
    private Task CopyRuleDetailsAsync(FirewallRuleRow? row) => CopyTextSafeAsync(row?.Tooltip);

    private async Task CopyTextSafeAsync(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value == "—")
        {
            return;
        }

        try
        {
            await _ui.CopyTextAsync(value, CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is
                     InvalidOperationException or NotSupportedException or System.Runtime.InteropServices.ExternalException)
        {
        }
    }

    private async Task ConfirmAndBlockAsync(string appPath, string appName)
    {
        var confirmed = await _ui.ConfirmAsync(
            "Block this application",
            $"Create an Axiom outbound {PlatformText.Firewall} block rule for:\n{appPath}\n\n" +
            "Only the Axiom-owned rule is changed. You can unblock it from Remembered Shield decisions at any time.",
            "Block",
            destructive: true,
            CancellationToken.None).ConfigureAwait(true);

        if (!confirmed)
        {
            return;
        }

        await ApplyDecisionAsync(appPath, appName, ProtectionDecisionAction.Block).ConfigureAwait(true);
    }

    private async Task ConfirmAndUnblockAsync(string appPath, string appName)
    {
        var confirmed = await _ui.ConfirmAsync(
            "Unblock this application",
            $"Remove the Axiom outbound block rule for:\n{appPath}\n\n" +
            $"This restores network access and records an allow decision. Only the Axiom-owned rule is changed; other {PlatformText.Firewall} rules are not touched.",
            "Unblock",
            destructive: false,
            CancellationToken.None).ConfigureAwait(true);

        if (!confirmed)
        {
            return;
        }

        await ApplyDecisionAsync(appPath, appName, ProtectionDecisionAction.Allow).ConfigureAwait(true);
    }

    private async Task ApplyDecisionAsync(
        string appPath,
        string appName,
        ProtectionDecisionAction action)
    {
        if (_client is null)
        {
            return;
        }

        IsShieldBusy = true;
        StatusText = action == ProtectionDecisionAction.Block
            ? $"{appName}: applying block..."
            : $"{appName}: removing the Axiom block...";
        try
        {
            var status = await _client
                .SendAsync<ProtectionStatus>(
                    IpcCommandTypes.ProtectionDecide,
                    new ProtectionDecideRequest
                    {
                        AppPath = appPath,
                        AppName = appName,
                        Action = action,
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            ApplyStatus(status);
            StatusText = status.LastError
                ?? (action == ProtectionDecisionAction.Block
                    ? $"{appName}: blocked (Axiom firewall rule applied)."
                    : $"{appName}: unblocked (allow decision recorded).");
            DismissAlertFocus();
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
            StatusText = action == ProtectionDecisionAction.Block
                ? $"Block failed: {exception.Message}"
                : $"Unblock failed: {exception.Message}";
        }
        finally
        {
            IsShieldBusy = false;
        }
    }

    /// <summary>
    /// Highlights the applications an alert was about and explains what triggered the navigation.
    /// The pending list is transient, so the banner also reports apps that are no longer waiting.
    /// </summary>
    public void FocusPendingApps(IReadOnlyList<string> appPaths)
    {
        ArgumentNullException.ThrowIfNull(appPaths);
        _alertFocusPaths = appPaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        ApplyAlertFocus(true);

        // Pull the current pending decisions; the page may have been opened long before the alert.
        _ = RefreshAsync();
    }

    /// <summary>Applies a fresh protection snapshot while the Firewall page is visible.</summary>
    public void UpdateProtectionStatus(ProtectionStatus status)
    {
        ApplyStatus(status);

        // Windows Firewall reports no filter enforcement: keep its refresh-on-demand page (no
        // periodic rules re-read, Recheck stays enabled). The live re-query is for OS filters.
        if (!OperatingSystem.IsWindows())
        {
            RefreshEnforcementIfStale(DateTimeOffset.UtcNow);
        }
    }

    /// <summary>
    /// How often the rules/enforcement section is re-queried while the page is visible. The filter
    /// connection state is live (review 2026-11-12 #4): a page opened while the extension was
    /// disconnected must not keep saying "disconnected" after it reconnected, and vice versa.
    /// </summary>
    public static readonly TimeSpan EnforcementRefreshInterval = TimeSpan.FromSeconds(5);

    /// <summary>
    /// When the rules/enforcement section was last queried (UTC); the reference point for
    /// <see cref="RefreshEnforcementIfStale"/>. Exposed so tests can derive their "now" from it
    /// instead of racing the wall clock.
    /// </summary>
    public DateTimeOffset LastEnforcementRefreshUtc { get; private set; }

    /// <summary>Re-queries rules + capability when the last query is older than <see cref="EnforcementRefreshInterval"/>.</summary>
    public void RefreshEnforcementIfStale(DateTimeOffset now)
    {
        if (now - LastEnforcementRefreshUtc < EnforcementRefreshInterval)
        {
            return;
        }

        _ = RefreshAsync();
    }

    [RelayCommand]
    private void DismissAlertFocus()
    {
        _alertFocusPaths = [];
        ApplyAlertFocus();
    }

    private void ApplyAlertFocus(bool requestScroll = false)
    {
        if (_alertFocusPaths.Length == 0)
        {
            HasAlertFocus = false;
            HasSingleFocusedPending = false;
            AlertFocusText = string.Empty;
            _focusedPending = null;
            return;
        }

        var focusSet = new HashSet<string>(_alertFocusPaths, StringComparer.OrdinalIgnoreCase);
        foreach (var row in Pending)
        {
            row.IsFocused = focusSet.Contains(row.AppPath);
        }

        var matched = Pending.Where(row => row.IsFocused).ToList();
        _focusedPending = matched.Count == 1 ? matched[0] : null;
        HasSingleFocusedPending = _focusedPending is not null;

        var names = matched.Count > 0
            ? string.Join(", ", matched.Take(3).Select(row => row.AppName))
            : string.Join(", ", _alertFocusPaths
                .Select(Path.GetFileName)
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Take(3));
        var total = matched.Count > 0 ? matched.Count : _alertFocusPaths.Length;
        var suffix = total > 3 ? $" (+{total - 3} more)" : string.Empty;

        HasAlertFocus = true;
        if (matched.Count == 0)
        {
            AlertFocusText =
                $"From the alert: {names}{suffix}. No pending decision remains for this application " +
                "(it was already decided or dismissed). Nothing was blocked automatically.";
        }
        else if (matched.Count == 1)
        {
            var app = matched[0];
            AlertFocusText =
                $"From the alert: {app.AppName} opened an outbound connection to {app.RemoteSummary}. " +
                $"{app.ConnectionText}. Axiom Shield is still waiting for a Block/Allow decision; " +
                "use Allow, Block or Dismiss below. Nothing is blocked automatically, and this is not a malware verdict.";
        }
        else
        {
            AlertFocusText =
                $"From the alert: {names}{suffix} are still waiting for a Block/Allow decision. " +
                "Use Allow, Block or Dismiss on each row below. Nothing is blocked automatically; " +
                "a dismissed application returns when it opens a new connection.";
        }

        // The page reuses one ScrollViewer, so a previous visit may leave it scrolled past the
        // banner. Ask the view to scroll to the top only when a new alert focus arrives.
        if (requestScroll)
        {
            Dispatcher.UIThread.Post(
                () => AlertFocusRequested?.Invoke(this, EventArgs.Empty),
                DispatcherPriority.Background);
        }
    }

    /// <summary>Raised when an alert focus should scroll the Firewall page back to the banner.</summary>
    public event EventHandler? AlertFocusRequested;

    private async Task DismissPendingCoreAsync(PendingAppRow row)
    {
        if (_client is null)
        {
            return;
        }

        IsShieldBusy = true;
        StatusText = $"{row.AppName}: dismissing the pending decision...";
        try
        {
            var status = await _client
                .SendAsync<ProtectionStatus>(
                    IpcCommandTypes.ProtectionDismiss,
                    new ProtectionDismissRequest
                    {
                        AppPath = row.AppPath,
                        AppName = row.AppName,
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            ApplyStatus(status);
            StatusText = status.LastError
                ?? $"{row.AppName}: dismissed. It will appear again if it opens a new connection.";
            if (_alertFocusPaths.Contains(row.AppPath, StringComparer.OrdinalIgnoreCase))
            {
                DismissAlertFocus();
            }

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
            StatusText = $"Dismiss failed: {exception.Message}";
        }
        finally
        {
            IsShieldBusy = false;
        }
    }

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
                $"Create a {PlatformText.Firewall} block rule for:\n{row.AppPath}\n\n" +
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
            DismissAlertFocus();
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

        ShieldStatusText = OperatingSystem.IsMacOS()
            ? "The Axiom daemon did not come up. Check 'sudo launchctl print system/com.axiom.service' and /Library/Logs/Axiom."
            : $"The Axiom service did not come up. {PlatformText.ServiceCheckHint}";
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
        var focusSet = new HashSet<string>(_alertFocusPaths, StringComparer.OrdinalIgnoreCase);
        var ignoredMicrosoft = 0;
        foreach (var app in status.Pending)
        {
            if (ShieldProcessFilter.IsIgnored(app.AppPath))
            {
                ignoredMicrosoft++;
                continue;
            }

            var enriched = ProtectionAlertContext.Enrich(app, _monitor?.Connections);
            Pending.Add(new PendingAppRow(enriched) { IsFocused = focusSet.Contains(app.AppPath) });
        }

        PendingCount = Pending.Count;
        IgnoredMicrosoftCount = ignoredMicrosoft;
        HasPending = PendingCount > 0;

        Decisions.Clear();
        foreach (var decision in status.Decisions.OrderByDescending(item => item.DecidedUtc))
        {
            Decisions.Add(new ShieldDecisionRow(decision));
        }

        DecisionCount = Decisions.Count;
        HasDecisions = DecisionCount > 0;
        ApplyAlertFocus();
        AgentPathCount = status.AgentPaths.Count;
        AgentLockdownHintText = AgentPathCount == 0
            ? "No agent executable is connected right now."
            : $"{AgentPathCount} agent executable(s) detected. Lockdown blocks internet access for these exact files and keeps localhost reachable; a renamed copy or another tool is not covered.";

        ShieldStatusText = !string.IsNullOrWhiteSpace(status.LastError)
            ? status.LastError!
            : status.Enabled
                ? $"Protection is on · {status.OwnedRuleCount} Axiom rule(s) · {PendingCount} new outbound application(s) with no Block/Allow decision."
                : "Protection is off. Axiom only observes.";

        ShieldHintText = !status.ServiceElevated
            ? (OperatingSystem.IsMacOS()
                ? "Enable installs the Axiom daemon (one administrator password). Until then Axiom can read rules but cannot enforce them."
                : $"Enable installs the Axiom {PlatformText.ServiceKind} (one administrator approval). Until then Axiom can read rules but cannot enforce them.")
            : status.Enabled
                ? $"Ask policy: a new outbound application waits above until you choose Block or Allow. Every block is a {PlatformText.Firewall} rule named Axiom::…."
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

    /// <summary>Re-reads the owned rules whenever the page is shown: rules created from Connections
    /// or Applications would otherwise only appear after Recheck.</summary>
    public void Activate()
    {
        if (_client is not null && !OperatingSystem.IsWindows())
        {
            _ = RefreshAsync();
        }
    }

    public void Deactivate()
    {
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        if (_client is null || IsBusy)
        {
            return;
        }

        IsBusy = true;
        LastEnforcementRefreshUtc = DateTimeOffset.UtcNow;

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
                ?? $"{(OperatingSystem.IsWindows() ? "Windows Firewall COM policy" : PlatformText.Firewall + " policy")} is readable. No rule is changed by this page.";
            OwnedRuleCountText = snapshot.Rules.Count.ToString(CultureInfo.InvariantCulture);
            IsEmpty = snapshot.Rules.Count == 0;
            WritesEnabled = snapshot.WritesEnabled;
            WritePathText = snapshot.WritesEnabled ? "enabled (test VM only)" : "disabled";
            HasError = snapshot.Capability.Status == FirewallCapabilityStatus.Unavailable;
            Enforcement = FilterEnforcementSummary.From(snapshot.Capability.FilterEnforcement);
            StatusText = snapshot.Rules.Count == 0
                ? $"0 owned rules. Axiom has not created any {PlatformText.Firewall} rule on this host."
                : $"{snapshot.Rules.Count} owned rules read at {DateTimeOffset.Now:HH:mm:ss}.";

            await RefreshShieldAsync().ConfigureAwait(true);
        }
        catch (ServiceUnavailableException exception)
        {
            Rules.Clear();
            Enforcement = FilterEnforcementSummary.None;
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
