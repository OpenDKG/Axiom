// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using Axiom.Contracts.Blackbox;
using Axiom.Presentation;
using CommunityToolkit.Mvvm.Input;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Streamlined home page for Simple mode: presents protection status, one-click Firewall/Privacy
/// controls, pending app requests, currently online apps, and live AI agent activity without technical jargon.
/// </summary>
public sealed partial class SimpleHomePageViewModel : PageViewModel, IActivatablePage, IDisposable
{
    private const int MaxRecentAgentEntries = 15;

    private readonly Action _openFirewall;
    private readonly Action _openPrivacyOverview;
    private readonly Action _openNetworkAdvanced;
    private readonly Action _switchToAdvanced;
    private readonly Action _openAgentsAdvanced;

    public SimpleHomePageViewModel(
        OverviewPageViewModel overview,
        FirewallPageViewModel firewall,
        PrivacyShieldPageViewModel privacyShield,
        AgentsPageViewModel agents,
        Action openFirewall,
        Action openPrivacyOverview,
        Action openNetworkAdvanced,
        Action switchToAdvanced,
        Action? openAgentsAdvanced = null)
        : base("Home", "Essential firewall, privacy blocker, network, and AI agent overview", "H")
    {
        Overview = overview ?? throw new ArgumentNullException(nameof(overview));
        Firewall = firewall ?? throw new ArgumentNullException(nameof(firewall));
        PrivacyShield = privacyShield ?? throw new ArgumentNullException(nameof(privacyShield));
        Agents = agents ?? throw new ArgumentNullException(nameof(agents));
        _openFirewall = openFirewall ?? throw new ArgumentNullException(nameof(openFirewall));
        _openPrivacyOverview = openPrivacyOverview ?? throw new ArgumentNullException(nameof(openPrivacyOverview));
        _openNetworkAdvanced = openNetworkAdvanced ?? throw new ArgumentNullException(nameof(openNetworkAdvanced));
        _switchToAdvanced = switchToAdvanced ?? throw new ArgumentNullException(nameof(switchToAdvanced));
        _openAgentsAdvanced = openAgentsAdvanced ?? switchToAdvanced;

        Firewall.PropertyChanged += OnChildPropertyChanged;
        PrivacyShield.PropertyChanged += OnChildPropertyChanged;
        Overview.PropertyChanged += OnChildPropertyChanged;
        Agents.PropertyChanged += OnChildPropertyChanged;
        Agents.Security.PropertyChanged += OnChildPropertyChanged;
        Overview.TopApps.CollectionChanged += OnTopAppsCollectionChanged;
        Agents.Activity.CollectionChanged += OnAgentActivityCollectionChanged;
        Agents.Security.ProtectedAgents.CollectionChanged += OnProtectedAgentsCollectionChanged;

        SyncRecentAgentActivity();
    }

    public OverviewPageViewModel Overview { get; }

    public FirewallPageViewModel Firewall { get; }

    public PrivacyShieldPageViewModel PrivacyShield { get; }

    public AgentsPageViewModel Agents { get; }

    public ObservableCollection<AppRow> TopApps => Overview.TopApps;

    public ObservableCollection<BlackboxAuditEntry> RecentAgentActivity { get; } = [];

    public bool HasOnlineApps => TopApps.Count > 0;

    public bool HasAgentActivity => RecentAgentActivity.Count > 0;

    public bool IsShieldActive => Firewall.ProtectionKnown && Firewall.ShieldEnabled;

    public bool IsFullyProtected => Firewall.ShieldLevel == EnforcementLevel.Protected && PrivacyShield.Enabled;

    /// <summary>Shield on, but the platform filter has not proven enforcement (off Windows only).</summary>
    public bool IsShieldUnverified => Firewall.ShieldLevel == EnforcementLevel.Degraded;

    public string HeroBadgeText => !Firewall.ProtectionKnown
        ? "STATUS UNKNOWN"
        : IsShieldUnverified
            ? "NOT VERIFIED"
            : Firewall.ShieldEnabled
            ? (PrivacyShield.Enabled ? "PROTECTED" : "SHIELD ACTIVE")
            : "MONITORING ONLY";

    public string HeroHeadlineText => !Firewall.ProtectionKnown
        ? "Protection status is unknown"
        : IsShieldUnverified
            ? "Shield is on, blocking is not verified"
            : Firewall.ShieldEnabled
            ? (PrivacyShield.Enabled ? "Your computer is protected" : "Firewall Shield is protecting your apps")
            : "Firewall protection is off";

    public string HeroSummaryText => !Firewall.ProtectionKnown
        ? "Axiom could not read the local service, so it cannot confirm whether Shield is on. Open Firewall to check."
        : IsShieldUnverified
            ? $"Axiom Shield is on, but {PlatformText.FilterName} has not confirmed enforcement yet ({Firewall.Enforcement.NotVerifiedReason}). Open Firewall to check."
            : Firewall.ShieldEnabled
            ? (PrivacyShield.Enabled
                ? "Axiom Shield checks new outbound apps and Privacy Shield is actively filtering ads and trackers."
                : "Axiom Shield asks before unfamiliar apps connect to the internet. You can also turn on the Ad & Tracker Blocker below.")
            : "Axiom is monitoring internet usage in read-only mode. Turn on Firewall Shield to control which apps may connect.";

    public string ShieldButtonText => !Firewall.ProtectionKnown
        ? "Check Firewall"
        : Firewall.ShieldEnabled ? "Turn Shield Off" : "Turn Shield On";

    public string FirewallStatusText => !Firewall.ProtectionKnown
        ? "Unknown — the local service did not answer"
        : Firewall.ShieldEnabled
            ? (Firewall.PendingCount > 0
                ? $"Active — {Firewall.PendingCount} app(s) waiting for your decision"
                : "Active — monitoring and guarding outbound apps")
            : Firewall.ShieldStatusText;

    public string PrivacyStatusText => PrivacyShield.Enabled
        ? $"Blocking {PrivacyShield.BlockedCountText} trackers & ads ({PrivacyShield.QueriesCountText} checks)"
        : PrivacyShield.IsSupported
            ? "Off — turn on to filter trackers, telemetry, and ads locally"
            : "Requires Axiom local service (--service) to filter DNS";

    public string PrivacyActionText => PrivacyShield.Enabled ? "Turn Off" : "Turn On";

    public bool CanTogglePrivacy => PrivacyShield.IsSupported && !PrivacyShield.IsBusy;

    public string AiGuardSummaryText =>
        Agents.Security.BlackboxConnected
            ? "AI Agent Guard is active and monitoring coding-assistant sessions locally."
            : "AI Agent modules are optional — switch to Advanced mode to inspect or configure them.";

    /// <summary>
    /// Off Windows no Blackbox host hook is proven yet, so agent protection is not verified: the
    /// tile never says READY there, and it never reads the firewall or BPF state (network
    /// enforcement is not agent protection). Only a verified host/OS deny reported by the
    /// enforcement controller may say ACTIVE. Windows keeps its wording.
    /// </summary>
    private static bool AgentGuardUnproven => !OperatingSystem.IsWindows();

    public string AgentGuardBadgeText =>
        AgentGuardUnproven
            ? Agents.Enforcement.CanClaimVerifiedBlocking ? "ACTIVE" : "NOT VERIFIED"
            : Agents.Security.BlackboxConnected || Agents.Enforcement.CanClaimVerifiedBlocking
            ? "ACTIVE"
            : Agents.Security.ProtectedAgents.Count > 0
                ? "DETECTED"
                : "READY";

    public string AgentGuardStatusText =>
        AgentGuardUnproven && !Agents.Enforcement.CanClaimVerifiedBlocking
            ? Agents.Security.BlackboxConnected
                ? $"Blackbox guard connected · {Agents.Security.ProtectedAgents.Count} AI tool(s) watched · blocking is not verified on {PlatformText.OsName}"
                : $"Unsupported on {PlatformText.OsName} for now: Blackbox host hooks are not verified here, so AI agents are not protected"
            : Agents.Security.BlackboxConnected
            ? $"{Agents.Security.ProtectedAgents.Count} AI tool(s) watched · {Agents.BlockedFindingCount} blocked threat(s)"
            : Agents.Security.ProtectedAgents.Count > 0
                ? $"{Agents.Security.ProtectedAgents.Count} local AI tool(s) found · {Agents.BlockedFindingCount} blocked"
                : "Watches AI coding tools and blocks risky commands or secret reads";

    public string AgentActivityCountText => $"{Agents.Activity.Count} events";

    public string AgentActivitySummaryText =>
        Agents.Activity.Count > 0
            ? $"{Agents.ToolCallCount} tool call(s) · {Agents.FileAccessCount} file check(s) · {Agents.BlockedFindingCount} blocked"
            : Agents.Security.BlackboxConnected
                ? "Agent Guard is listening — tool calls, file checks, and blocks will appear here."
                : "No recent AI agent activity has been recorded yet.";

    public void Activate()
    {
        (Overview as IActivatablePage).Activate();
        (PrivacyShield as IActivatablePage).Activate();
        (Agents as IActivatablePage).Activate();
    }

    public void Deactivate()
    {
        (Overview as IActivatablePage).Deactivate();
        (PrivacyShield as IActivatablePage).Deactivate();
        (Agents as IActivatablePage).Deactivate();
    }

    [RelayCommand]
    private void ToggleShield()
    {
        if (!Firewall.ProtectionKnown)
        {
            _openFirewall();
            return;
        }

        if (Firewall.ToggleShieldCommand.CanExecute(null))
        {
            Firewall.ToggleShieldCommand.Execute(null);
        }
    }

    [RelayCommand]
    private void TogglePrivacy()
    {
        if (!PrivacyShield.IsSupported || PrivacyShield.IsBusy)
        {
            return;
        }

        if (PrivacyShield.Enabled)
        {
            if (PrivacyShield.DisableCommand.CanExecute(null))
            {
                PrivacyShield.DisableCommand.Execute(null);
            }
        }
        else
        {
            PrivacyShield.Enabled = true;
            if (PrivacyShield.ApplyCommand.CanExecute(null))
            {
                PrivacyShield.ApplyCommand.Execute(null);
            }
        }
    }

    [RelayCommand]
    private void OpenFirewall() => _openFirewall();

    [RelayCommand]
    private void OpenPrivacy() => _openPrivacyOverview();

    [RelayCommand]
    private void OpenNetworkAdvanced() => _openNetworkAdvanced();

    [RelayCommand]
    private void OpenAgents() => _openAgentsAdvanced();

    [RelayCommand]
    private void SwitchToAdvanced() => _switchToAdvanced();

    public void Dispose()
    {
        Firewall.PropertyChanged -= OnChildPropertyChanged;
        PrivacyShield.PropertyChanged -= OnChildPropertyChanged;
        Overview.PropertyChanged -= OnChildPropertyChanged;
        Agents.PropertyChanged -= OnChildPropertyChanged;
        Agents.Security.PropertyChanged -= OnChildPropertyChanged;
        Overview.TopApps.CollectionChanged -= OnTopAppsCollectionChanged;
        Agents.Activity.CollectionChanged -= OnAgentActivityCollectionChanged;
        Agents.Security.ProtectedAgents.CollectionChanged -= OnProtectedAgentsCollectionChanged;
    }

    private void OnTopAppsCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        OnPropertyChanged(nameof(HasOnlineApps));
    }

    private void OnAgentActivityCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        SyncRecentAgentActivity();
        OnPropertyChanged(nameof(AgentActivityCountText));
        OnPropertyChanged(nameof(AgentActivitySummaryText));
    }

    private void OnProtectedAgentsCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        OnPropertyChanged(nameof(AgentGuardBadgeText));
        OnPropertyChanged(nameof(AgentGuardStatusText));
    }

    private void SyncRecentAgentActivity()
    {
        RecentAgentActivity.Clear();
        var count = Math.Min(MaxRecentAgentEntries, Agents.Activity.Count);
        for (var i = 0; i < count; i++)
        {
            RecentAgentActivity.Add(Agents.Activity[i]);
        }

        OnPropertyChanged(nameof(HasAgentActivity));
    }

    private void OnChildPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        OnPropertyChanged(nameof(IsShieldActive));
        OnPropertyChanged(nameof(IsFullyProtected));
        OnPropertyChanged(nameof(IsShieldUnverified));
        OnPropertyChanged(nameof(HeroBadgeText));
        OnPropertyChanged(nameof(HeroHeadlineText));
        OnPropertyChanged(nameof(HeroSummaryText));
        OnPropertyChanged(nameof(ShieldButtonText));
        OnPropertyChanged(nameof(FirewallStatusText));
        OnPropertyChanged(nameof(PrivacyStatusText));
        OnPropertyChanged(nameof(PrivacyActionText));
        OnPropertyChanged(nameof(CanTogglePrivacy));
        OnPropertyChanged(nameof(AiGuardSummaryText));
        OnPropertyChanged(nameof(AgentGuardBadgeText));
        OnPropertyChanged(nameof(AgentGuardStatusText));
        OnPropertyChanged(nameof(AgentActivityCountText));
        OnPropertyChanged(nameof(AgentActivitySummaryText));
    }
}
