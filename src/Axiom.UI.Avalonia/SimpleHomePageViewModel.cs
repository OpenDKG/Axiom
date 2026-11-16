// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Streamlined home page for Simple mode: presents protection status, one-click Firewall/Privacy
/// controls, pending app requests, and currently online apps without technical jargon.
/// </summary>
public sealed partial class SimpleHomePageViewModel : PageViewModel, IActivatablePage, IDisposable
{
    private readonly Action _openFirewall;
    private readonly Action _openPrivacyOverview;
    private readonly Action _openNetworkAdvanced;
    private readonly Action _switchToAdvanced;

    public SimpleHomePageViewModel(
        OverviewPageViewModel overview,
        FirewallPageViewModel firewall,
        PrivacyShieldPageViewModel privacyShield,
        AgentsPageViewModel agents,
        Action openFirewall,
        Action openPrivacyOverview,
        Action openNetworkAdvanced,
        Action switchToAdvanced)
        : base("Home", "Essential firewall, privacy blocker, and live network overview", "H")
    {
        Overview = overview ?? throw new ArgumentNullException(nameof(overview));
        Firewall = firewall ?? throw new ArgumentNullException(nameof(firewall));
        PrivacyShield = privacyShield ?? throw new ArgumentNullException(nameof(privacyShield));
        Agents = agents ?? throw new ArgumentNullException(nameof(agents));
        _openFirewall = openFirewall ?? throw new ArgumentNullException(nameof(openFirewall));
        _openPrivacyOverview = openPrivacyOverview ?? throw new ArgumentNullException(nameof(openPrivacyOverview));
        _openNetworkAdvanced = openNetworkAdvanced ?? throw new ArgumentNullException(nameof(openNetworkAdvanced));
        _switchToAdvanced = switchToAdvanced ?? throw new ArgumentNullException(nameof(switchToAdvanced));

        Firewall.PropertyChanged += OnChildPropertyChanged;
        PrivacyShield.PropertyChanged += OnChildPropertyChanged;
        Overview.PropertyChanged += OnChildPropertyChanged;
        Agents.Security.PropertyChanged += OnChildPropertyChanged;
        Overview.TopApps.CollectionChanged += OnTopAppsCollectionChanged;
    }

    public OverviewPageViewModel Overview { get; }

    public FirewallPageViewModel Firewall { get; }

    public PrivacyShieldPageViewModel PrivacyShield { get; }

    public AgentsPageViewModel Agents { get; }

    public ObservableCollection<AppRow> TopApps => Overview.TopApps;

    public bool HasOnlineApps => TopApps.Count > 0;

    public bool IsShieldActive => Firewall.ShieldEnabled;

    public bool IsFullyProtected => Firewall.ShieldEnabled && PrivacyShield.Enabled;

    public string HeroBadgeText => Firewall.ShieldEnabled
        ? (PrivacyShield.Enabled ? "PROTECTED" : "SHIELD ACTIVE")
        : "MONITORING ONLY";

    public string HeroHeadlineText => Firewall.ShieldEnabled
        ? (PrivacyShield.Enabled ? "Your computer is protected" : "Firewall Shield is protecting your apps")
        : "Firewall protection is off";

    public string HeroSummaryText => Firewall.ShieldEnabled
        ? (PrivacyShield.Enabled
            ? "Axiom Shield checks new outbound apps and Privacy Shield is actively filtering ads and trackers."
            : "Axiom Shield asks before unfamiliar apps connect to the internet. You can also turn on the Ad & Tracker Blocker below.")
        : "Axiom is monitoring internet usage in read-only mode. Turn on Firewall Shield to control which apps may connect.";

    public string ShieldButtonText => Firewall.ShieldEnabled ? "Turn Shield Off" : "Turn Shield On";

    public string FirewallStatusText => Firewall.ShieldEnabled
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

    public void Activate()
    {
        (Overview as IActivatablePage).Activate();
        (PrivacyShield as IActivatablePage).Activate();
    }

    public void Deactivate()
    {
        (Overview as IActivatablePage).Deactivate();
        (PrivacyShield as IActivatablePage).Deactivate();
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
    private void OpenPrivacy() => _openPrivacyOverview();

    [RelayCommand]
    private void OpenNetworkAdvanced() => _openNetworkAdvanced();

    [RelayCommand]
    private void SwitchToAdvanced() => _switchToAdvanced();

    public void Dispose()
    {
        Firewall.PropertyChanged -= OnChildPropertyChanged;
        PrivacyShield.PropertyChanged -= OnChildPropertyChanged;
        Overview.PropertyChanged -= OnChildPropertyChanged;
        Agents.Security.PropertyChanged -= OnChildPropertyChanged;
        Overview.TopApps.CollectionChanged -= OnTopAppsCollectionChanged;
    }

    private void OnTopAppsCollectionChanged(object? sender, System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
    {
        OnPropertyChanged(nameof(HasOnlineApps));
    }

    private void OnChildPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        OnPropertyChanged(nameof(IsShieldActive));
        OnPropertyChanged(nameof(IsFullyProtected));
        OnPropertyChanged(nameof(HeroBadgeText));
        OnPropertyChanged(nameof(HeroHeadlineText));
        OnPropertyChanged(nameof(HeroSummaryText));
        OnPropertyChanged(nameof(ShieldButtonText));
        OnPropertyChanged(nameof(FirewallStatusText));
        OnPropertyChanged(nameof(PrivacyStatusText));
        OnPropertyChanged(nameof(PrivacyActionText));
        OnPropertyChanged(nameof(CanTogglePrivacy));
        OnPropertyChanged(nameof(AiGuardSummaryText));
    }
}
