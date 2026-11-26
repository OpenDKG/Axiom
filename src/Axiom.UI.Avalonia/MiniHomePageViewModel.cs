// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;
using Axiom.Contracts.Blackbox;
using Axiom.Presentation;
using CommunityToolkit.Mvvm.Input;

namespace Axiom.UI.Avalonia;

public sealed record MiniBlockedNetworkItem(string Title, string Detail, string Badge);

/// <summary>
/// Compact widget-like home page for Mini mode showing only blocked/pending items across
/// Network, AI Agents, and Privacy alongside quick protection toggles and core links.
/// </summary>
public sealed partial class MiniHomePageViewModel : PageViewModel, IActivatablePage, IDisposable
{
    private const int MaxItemsPerSection = 8;

    private const int MaxRecentAgentEntries = 4;

    private readonly Action _openFirewall;
    private readonly Action _openPrivacy;
    private readonly Action _openAgents;
    private readonly Action _openSettings;
    private readonly Action _openSupport;
    private readonly Action _openWebsite;
    private readonly Func<Task> _openGitHub;
    private readonly Action _expandView;

    public MiniHomePageViewModel(
        OverviewPageViewModel overview,
        FirewallPageViewModel firewall,
        PrivacyShieldPageViewModel privacyShield,
        AgentsPageViewModel agents,
        string versionText,
        Action openFirewall,
        Action openPrivacy,
        Action openAgents,
        Action openSettings,
        Action openSupport,
        Action openWebsite,
        Func<Task> openGitHub,
        Action expandView)
        : base("Mini", "Compact blocked activity monitor", "M")
    {
        Overview = overview ?? throw new ArgumentNullException(nameof(overview));
        Firewall = firewall ?? throw new ArgumentNullException(nameof(firewall));
        PrivacyShield = privacyShield ?? throw new ArgumentNullException(nameof(privacyShield));
        Agents = agents ?? throw new ArgumentNullException(nameof(agents));
        VersionText = versionText ?? string.Empty;
        _openFirewall = openFirewall ?? throw new ArgumentNullException(nameof(openFirewall));
        _openPrivacy = openPrivacy ?? throw new ArgumentNullException(nameof(openPrivacy));
        _openAgents = openAgents ?? throw new ArgumentNullException(nameof(openAgents));
        _openSettings = openSettings ?? throw new ArgumentNullException(nameof(openSettings));
        _openSupport = openSupport ?? throw new ArgumentNullException(nameof(openSupport));
        _openWebsite = openWebsite ?? throw new ArgumentNullException(nameof(openWebsite));
        _openGitHub = openGitHub ?? throw new ArgumentNullException(nameof(openGitHub));
        _expandView = expandView ?? throw new ArgumentNullException(nameof(expandView));

        Firewall.PropertyChanged += OnChildPropertyChanged;
        PrivacyShield.PropertyChanged += OnChildPropertyChanged;
        Agents.PropertyChanged += OnChildPropertyChanged;
        Agents.Security.PropertyChanged += OnChildPropertyChanged;
        Firewall.Rules.CollectionChanged += OnFirewallCollectionChanged;
        Firewall.Decisions.CollectionChanged += OnFirewallCollectionChanged;
        Firewall.Pending.CollectionChanged += OnFirewallCollectionChanged;
        Agents.Activity.CollectionChanged += OnAgentsCollectionChanged;
        PrivacyShield.RecentBlockedGroups.CollectionChanged += OnPrivacyCollectionChanged;

        SyncBlockedNetwork();
        SyncBlockedAgents();
        SyncBlockedPrivacy();
        SyncRecentAgentActivity();
    }

    public FirewallPageViewModel Firewall { get; }

    public PrivacyShieldPageViewModel PrivacyShield { get; }

    public AgentsPageViewModel Agents { get; }

    public OverviewPageViewModel Overview { get; }

    public string VersionText { get; }

    public ObservableCollection<MiniBlockedNetworkItem> BlockedNetwork { get; } = [];

    public ObservableCollection<BlackboxAuditEntry> BlockedAgents { get; } = [];

    /// <summary>The last few guard-observed actions, shown under the throughput chart.</summary>
    public ObservableCollection<BlackboxAuditEntry> RecentAgentActivity { get; } = [];

    public bool HasAgentActivity => RecentAgentActivity.Count > 0;

    public ObservableCollection<RecentBlockedGroup> BlockedPrivacy { get; } = [];

    public bool HasBlockedNetwork => BlockedNetwork.Count > 0;

    public bool HasBlockedAgents => BlockedAgents.Count > 0;

    public bool HasBlockedPrivacy => BlockedPrivacy.Count > 0;

    // While the service has not answered the shield state is unknown, not OFF.
    public string ShieldButtonText => !Firewall.ProtectionKnown
        ? "Shield: unknown"
        : Firewall.ShieldEnabled ? "Shield: ON" : "Shield: OFF";

    /// <summary>Shield entry of the module health row, same model as the header lamp.</summary>
    public string ShieldLevelText => ShieldProtection.ShieldText(Firewall.ShieldLevel, Firewall.VerifiedByOs);

    public bool IsShieldToneOk => ShieldProtection.Tone(Firewall.ShieldLevel) == "ok";

    public bool IsShieldToneWarn => ShieldProtection.Tone(Firewall.ShieldLevel) == "warn";

    public bool IsShieldToneFail => ShieldProtection.Tone(Firewall.ShieldLevel) == "fail";

    public bool IsShieldToneIdle => ShieldProtection.Tone(Firewall.ShieldLevel) == "idle";

    public string PrivacyButtonText => PrivacyShield.Enabled ? "Privacy: ON" : "Privacy: OFF";

    public bool CanTogglePrivacy => PrivacyShield.IsSupported && !PrivacyShield.IsBusy;

    public string NetworkBlockedCountText
    {
        get
        {
            var count = Math.Max(
                BlockedNetwork.Count,
                Firewall.Rules.Count(r => r.IsBlock) + Firewall.Decisions.Count(d => d.IsBlock));
            return count.ToString(CultureInfo.InvariantCulture) + " blocked";
        }
    }

    public string AgentsBlockedCountText =>
        Math.Max(Agents.BlockSummary.Blocked, BlockedAgents.Count).ToString("N0", CultureInfo.InvariantCulture) + " blocked";

    public string PrivacyBlockedCountText => PrivacyShield.BlockedCountText + " blocked";

    public void Activate()
    {
        Overview.ActivateSummary();
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
    private void OpenPrivacy() => _openPrivacy();

    [RelayCommand]
    private void OpenAgents() => _openAgents();

    [RelayCommand]
    private void OpenSettings() => _openSettings();

    [RelayCommand]
    private void OpenSupport() => _openSupport();

    [RelayCommand]
    private Task OpenGitHubAsync() => _openGitHub();

    [RelayCommand]
    private void Expand() => _expandView();

    public void Dispose()
    {
        Firewall.PropertyChanged -= OnChildPropertyChanged;
        PrivacyShield.PropertyChanged -= OnChildPropertyChanged;
        Agents.PropertyChanged -= OnChildPropertyChanged;
        Agents.Security.PropertyChanged -= OnChildPropertyChanged;
        Firewall.Rules.CollectionChanged -= OnFirewallCollectionChanged;
        Firewall.Decisions.CollectionChanged -= OnFirewallCollectionChanged;
        Firewall.Pending.CollectionChanged -= OnFirewallCollectionChanged;
        Agents.Activity.CollectionChanged -= OnAgentsCollectionChanged;
        PrivacyShield.RecentBlockedGroups.CollectionChanged -= OnPrivacyCollectionChanged;
    }

    private void OnFirewallCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        SyncBlockedNetwork();
        OnPropertyChanged(nameof(NetworkBlockedCountText));
    }

    private void OnAgentsCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        SyncBlockedAgents();
        SyncRecentAgentActivity();
        OnPropertyChanged(nameof(AgentsBlockedCountText));
    }

    [RelayCommand]
    private void OpenWebsite() => _openWebsite();

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

    private void OnPrivacyCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        SyncBlockedPrivacy();
        OnPropertyChanged(nameof(PrivacyBlockedCountText));
    }

    private void OnChildPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        OnPropertyChanged(nameof(ShieldButtonText));
        OnPropertyChanged(nameof(ShieldLevelText));
        OnPropertyChanged(nameof(IsShieldToneOk));
        OnPropertyChanged(nameof(IsShieldToneWarn));
        OnPropertyChanged(nameof(IsShieldToneFail));
        OnPropertyChanged(nameof(IsShieldToneIdle));
        OnPropertyChanged(nameof(PrivacyButtonText));
        OnPropertyChanged(nameof(CanTogglePrivacy));
        OnPropertyChanged(nameof(NetworkBlockedCountText));
        OnPropertyChanged(nameof(AgentsBlockedCountText));
        OnPropertyChanged(nameof(PrivacyBlockedCountText));
    }

    private void SyncBlockedNetwork()
    {
        BlockedNetwork.Clear();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in Firewall.Rules)
        {
            if (!rule.IsBlock || !seen.Add(rule.Application + "|" + rule.DirectionText))
            {
                continue;
            }

            BlockedNetwork.Add(new MiniBlockedNetworkItem(
                rule.Application,
                $"{rule.DirectionText} · {rule.ProtocolText} · ports {rule.PortsText}",
                "BLOCKED"));
            if (BlockedNetwork.Count >= MaxItemsPerSection)
            {
                break;
            }
        }

        if (BlockedNetwork.Count < MaxItemsPerSection)
        {
            foreach (var decision in Firewall.Decisions)
            {
                if (!decision.IsBlock || !seen.Add(decision.AppName + "|Out"))
                {
                    continue;
                }

                BlockedNetwork.Add(new MiniBlockedNetworkItem(
                    decision.AppName,
                    $"Shield rule · {decision.DecidedText}",
                    "BLOCKED"));
                if (BlockedNetwork.Count >= MaxItemsPerSection)
                {
                    break;
                }
            }
        }

        OnPropertyChanged(nameof(HasBlockedNetwork));
    }

    private void SyncBlockedAgents()
    {
        BlockedAgents.Clear();
        foreach (var entry in Agents.Activity)
        {
            if (!entry.IsBlocked && !entry.IsThreat)
            {
                continue;
            }

            BlockedAgents.Add(entry);
            if (BlockedAgents.Count >= MaxItemsPerSection)
            {
                break;
            }
        }

        OnPropertyChanged(nameof(HasBlockedAgents));
    }

    private void SyncBlockedPrivacy()
    {
        BlockedPrivacy.Clear();
        foreach (var group in PrivacyShield.RecentBlockedGroups)
        {
            BlockedPrivacy.Add(group);
            if (BlockedPrivacy.Count >= MaxItemsPerSection)
            {
                break;
            }
        }

        OnPropertyChanged(nameof(HasBlockedPrivacy));
    }
}
