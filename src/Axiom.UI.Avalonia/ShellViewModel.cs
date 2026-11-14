// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Contracts.Agents;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Modules;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Contracts.Protection;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Avalonia shell for the first migration slice. The WPF shell remains the reference until every
/// page is ported; this shell deliberately exposes only the pages that have real implementations.
/// </summary>
public sealed partial class ShellViewModel : ObservableObject, IDisposable
{
    private readonly ConnectionMonitor _monitor;
    private readonly TrafficEngine _traffic;
    private readonly ServiceStatusProbe? _serviceProbe;
    private readonly IServiceRequestClient? _serviceClient;
    private readonly IUserInteraction _ui;
    private readonly IThemeService _theme;
    private readonly IVisualEffectsService _visualEffects;
    private readonly CancellationTokenSource _cancellation = new();
    private DateTimeOffset _lastProbeUtc = DateTimeOffset.MinValue;
    private DateTimeOffset _lastProtectionProbeUtc = DateTimeOffset.MinValue;
    private bool _isProbing;
    private bool _isProbingProtection;
    private bool _updatingTheme;
    private ProtectionStatus? _protection;
    private readonly HashSet<string> _notifiedPendingApps = new(StringComparer.OrdinalIgnoreCase);

    public ShellViewModel(
        IConnectionSnapshotSource source,
        IUiTimerFactory timers,
        ServiceStatusProbe? serviceProbe = null,
        IServiceRequestClient? serviceClient = null,
        IUserInteraction? userInteraction = null,
        IProcessActions? processActions = null,
        IThemeService? themeService = null,
        IAutostartService? autostartService = null,
        IApiKeyProtector? apiKeyProtector = null,
        IDnsAdapterHelper? dnsAdapterHelper = null,
        ISecurityDialogService? securityDialogs = null,
        IShellActions? shellActions = null,
        IBlackboxDialogService? blackboxDialogs = null,
        IAgentSessionSource? agentSessions = null,
        IVisualEffectsService? visualEffects = null,
        Func<CancellationToken, Task<NetworkRecoveryRestoreResult>>? restoreNetwork = null,
        ILoopbackListenerInspector? listenerInspector = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(timers);
        _monitor = new ConnectionMonitor(source, timers);
        _traffic = new TrafficEngine(timers);
        _serviceProbe = serviceProbe;
        _serviceClient = serviceClient;
        IsServiceMode = source is ServiceSnapshotSource;
        var interaction = userInteraction ?? new NullUserInteraction();
        _ui = interaction;
        _theme = themeService ?? new FixedThemeService();
        _visualEffects = visualEffects ?? new FixedVisualEffectsService();
        var processes = processActions ?? new UnsupportedProcessActions();
        Overview = new OverviewPageViewModel(
            _monitor,
            _traffic,
            interaction,
            IsServiceMode ? serviceClient : null,
            processes);
        Connections = new ConnectionsPageViewModel(
            _monitor,
            interaction,
            IsServiceMode ? serviceClient : null,
            processes);
        Apps = new AppsPageViewModel(
            _monitor,
            IsServiceMode ? serviceClient : null,
            interaction,
            processes);
        Events = new EventsPageViewModel(
            IsServiceMode ? serviceClient : null,
            timers,
            interaction,
            processes);
        Firewall = new FirewallPageViewModel(IsServiceMode ? serviceClient : null, interaction, _monitor);
        PrivacyShield = new PrivacyShieldPageViewModel(
            IsServiceMode ? serviceClient : null,
            interaction,
            dnsAdapterHelper ?? new UnsupportedDnsAdapterHelper(),
            timers);
        // Review #25: the Overview line follows the same state as the "SHIELD ON" badge.
        Overview.ProtectionState = () => new OverviewProtectionState(
            FirewallWritesEnabled: Firewall.WritesEnabled,
            FirewallProtectionActive: _protection is { Enabled: true },
            PrivacyShieldActive: PrivacyShield.IsResolverActive,
            Enforcement: OperatingSystem.IsWindows() ? null : Firewall.Enforcement);
        Security = new SecurityPageViewModel(
            interaction,
            securityDialogs ?? new UnsupportedSecurityDialogs(),
            apiKeyProtector ?? new UnsupportedApiKeyProtector(),
            timers,
            shellActions ?? new UnsupportedShellActions(),
            serviceClient,
            listenerInspector);
        Agents = new AgentsPageViewModel(
            Security,
            agentSessions,
            interaction,
            blackboxDialogs ?? new UnsupportedBlackboxDialogs(),
            timers,
            serviceClient);
        AiAnalyst = new AiAnalystPageViewModel(
            _monitor,
            apiKeyProtector ?? new UnsupportedApiKeyProtector(),
            timers,
            interaction,
            IsServiceMode ? serviceClient : null);
        Support = new SupportPageViewModel(interaction);
        Settings = new SettingsPageViewModel(
            _monitor,
            IsServiceMode,
            _theme,
            autostartService ?? new UnsupportedAutostartService(),
            Firewall,
            interaction,
            _visualEffects,
            restoreNetwork);
        AgentStats = new AgentStatsPageViewModel(Agents);
        AgentDashboard = new AgentDashboardPageViewModel(Agents);
        AgentHealth = new AgentHealthPageViewModel(Agents, Security);
        Pages =
        [
            AgentDashboard,
            Overview,
            Connections,
            Apps,
            Events,
            Agents,
            AgentStats,
            AgentHealth,
            Firewall,
            PrivacyShield,
            AiAnalyst,
            Security,
            Settings,
            Support,
        ];

        // Navigation groups follow the UI terminology audit; only the first page of a group
        // carries the header so the nav list keeps one selection model.
        AgentDashboard.GroupLabel = "OVERVIEW";
        Connections.GroupLabel = "MONITORING";
        Agents.GroupLabel = "PROTECTION";
        AiAnalyst.GroupLabel = "INTELLIGENCE";
        Settings.GroupLabel = "GENERAL";
        _selectedPage = AgentDashboard;
        _activePage = AgentDashboard;
        _selectedTheme = ThemeLabel(_theme.Current);
        _theme.Changed += OnThemeChanged;
        _monitor.Updated += OnMonitorUpdated;
        AlertCenter.Changed += OnAlertCenterChanged;
    }

    public IReadOnlyList<string> Themes { get; } =
        ["Axiom Glass Dark", "Axiom Glass Light", "Dark", "Light", "Dark Midnight", "Light Warm"];

    /// <summary>Visual-effects preference plus the backdrop the host confirmed.</summary>
    public IVisualEffectsService VisualEffects => _visualEffects;

    /// <summary>True only for the two Axiom Glass palettes; the window requests blur for these.</summary>
    public bool IsGlassTheme => _theme.Current is UiTheme.GlassDark or UiTheme.GlassLight;

    /// <summary>True for the light glass palette, which uses a softer shadow.</summary>
    public bool IsGlassLight => _theme.Current == UiTheme.GlassLight;

    [ObservableProperty]
    private string _selectedTheme;

    partial void OnSelectedThemeChanged(string value)
    {
        if (_updatingTheme)
        {
            return;
        }

        _theme.Apply(value switch
        {
            "Light" => UiTheme.Light,
            "Dark Midnight" => UiTheme.DarkMidnight,
            "Light Warm" => UiTheme.LightWarm,
            "Axiom Glass Light" => UiTheme.GlassLight,
            "Axiom Glass Dark" => UiTheme.GlassDark,
            _ => UiTheme.Dark,
        });
    }

    [RelayCommand]
    private async Task OpenGitHubAsync()
    {
        try
        {
            await _ui.OpenExternalAsync("https://github.com/a-51-50/Axiom", CancellationToken.None)
                .ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is
                     InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
        {
            // No browser handler is available; leave the shell usable.
        }
    }

    [RelayCommand]
    private void OpenSupport() => SelectedPage = Support;

    private void OnThemeChanged(object? sender, EventArgs e)
    {
        _updatingTheme = true;
        SelectedTheme = ThemeLabel(_theme.Current);
        _updatingTheme = false;
        OnPropertyChanged(nameof(IsGlassTheme));
        OnPropertyChanged(nameof(IsGlassLight));
    }

    private static string ThemeLabel(UiTheme theme) => theme switch
    {
        UiTheme.Light => "Light",
        UiTheme.DarkMidnight => "Dark Midnight",
        UiTheme.LightWarm => "Light Warm",
        UiTheme.GlassDark => "Axiom Glass Dark",
        UiTheme.GlassLight => "Axiom Glass Light",
        _ => "Dark",
    };

    public AgentDashboardPageViewModel AgentDashboard { get; }

    public OverviewPageViewModel Overview { get; }

    public ConnectionsPageViewModel Connections { get; }

    public AppsPageViewModel Apps { get; }

    public EventsPageViewModel Events { get; }

    public FirewallPageViewModel Firewall { get; }

    public PrivacyShieldPageViewModel PrivacyShield { get; }

    public SecurityPageViewModel Security { get; }

    public AgentsPageViewModel Agents { get; }

    public AgentStatsPageViewModel AgentStats { get; }

    public AgentHealthPageViewModel AgentHealth { get; }

    public AiAnalystPageViewModel AiAnalyst { get; }

    public SupportPageViewModel Support { get; }

    public SettingsPageViewModel Settings { get; }

    public ObservableCollection<PageViewModel> Pages { get; }

    [ObservableProperty]
    private PageViewModel _selectedPage;

    partial void OnSelectedPageChanged(PageViewModel value)
    {
        (_activePage as IActivatablePage)?.Deactivate();
        _activePage = value;
        (value as IActivatablePage)?.Activate();
    }

    private PageViewModel? _activePage;

    [ObservableProperty]
    private string _statusMonitoringText = "Monitoring: starting";

    [ObservableProperty]
    private string _statusSourceText = "Data source: starting";

    [ObservableProperty]
    private string _statusIpcText = "IPC: not connected";

    [ObservableProperty]
    private string _statusStorageText = "Database: not connected";

    [ObservableProperty]
    private string _statusFirewallText = "Firewall writes: read-only";

    [ObservableProperty]
    private string _footerText = "Local only · no driver · no telemetry · no remote access.";

    [ObservableProperty]
    private string _statusModeText = "In-process monitor";

    [ObservableProperty]
    private string _statusFirewallBadgeText = "READ-ONLY";

    public bool IsServiceMode { get; }

    public ServiceStatusSnapshot? ServiceStatus { get; private set; }

    public string VersionText =>
        $"v{typeof(ShellViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"}";

    public void Start()
    {
        _monitor.Start();
        _traffic.Start();
        Overview.Refresh();
        foreach (var page in Pages)
        {
            if (!ReferenceEquals(page, SelectedPage))
            {
                (page as IActivatablePage)?.Deactivate();
            }
        }

        _activePage = SelectedPage;
        (SelectedPage as IActivatablePage)?.Activate();
        RefreshStatus();
        _ = ProbeServiceAsync(force: true);
    }

    public void Dispose()
    {
        _monitor.Updated -= OnMonitorUpdated;
        _theme.Changed -= OnThemeChanged;
        AlertCenter.Changed -= OnAlertCenterChanged;
        _cancellation.Cancel();
        _cancellation.Dispose();
        Overview.Dispose();
        Connections.Dispose();
        Apps.Dispose();
        Events.Dispose();
        Firewall.Dispose();
        PrivacyShield.Dispose();
        Security.Dispose();
        Agents.Dispose();
        AiAnalyst.Dispose();
        Settings.Dispose();
        _traffic.Dispose();
        _monitor.Dispose();
    }

    private void OnMonitorUpdated(object? sender, EventArgs e)
    {
        RefreshStatus();
        _ = ProbeServiceAsync();
        _ = ProbeProtectionAsync();
    }

    private async Task ProbeProtectionAsync()
    {
        if (_serviceClient is null || _isProbingProtection)
        {
            return;
        }

        if (DateTimeOffset.UtcNow - _lastProtectionProbeUtc < TimeSpan.FromSeconds(5))
        {
            return;
        }

        _isProbingProtection = true;
        _lastProtectionProbeUtc = DateTimeOffset.UtcNow;

        try
        {
            _protection = await _serviceClient
                .SendAsync<ProtectionStatus>(IpcCommandTypes.ProtectionStatus, null, _cancellation.Token)
                .ConfigureAwait(true);
            RefreshStatus();
            NotifyNewPendingApps(_protection);
            if (_protection is not null && ReferenceEquals(SelectedPage, Firewall))
            {
                Firewall.UpdateProtectionStatus(_protection);
            }
        }
        catch (ServiceUnavailableException)
        {
            _protection = null;
        }
#pragma warning disable CA1031 // An older service build simply does not expose the shield yet.
        catch (Exception)
#pragma warning restore CA1031
        {
            _protection = null;
        }
        finally
        {
            _isProbingProtection = false;
        }
    }

    /// <summary>
    /// Raises the tray toast when Axiom Shield starts waiting on new applications. A burst of
    /// pending sockets is aggregated into one alert so the notification area cannot be flooded.
    /// </summary>
    private void NotifyNewPendingApps(ProtectionStatus? protection)
    {
        if (protection is not { Enabled: true } || protection.Pending.Count == 0)
        {
            return;
        }

        var pending = protection.Pending
            .Where(app => !ShieldProcessFilter.IsIgnored(app.AppPath))
            .ToList();
        if (pending.Count == 0)
        {
            return;
        }

        var current = new HashSet<string>(
            pending.Select(app => app.AppPath),
            StringComparer.OrdinalIgnoreCase);
        var newApps = pending
            .Where(app => !_notifiedPendingApps.Contains(app.AppPath))
            .Select(app => ProtectionAlertContext.Enrich(app, _monitor.Connections))
            .ToList();

        // Decisions already made drop out, so an application that appears again can alert again.
        _notifiedPendingApps.IntersectWith(current);
        foreach (var app in newApps)
        {
            _notifiedPendingApps.Add(app.AppPath);
        }

        if (newApps.Count == 0)
        {
            return;
        }

        var names = string.Join(", ", newApps.Take(3).Select(app => app.AppName));
        var suffix = newApps.Count > 3 ? $" (+{newApps.Count - 3} more)" : string.Empty;
        var message = newApps.Count == 1
            ? $"{newApps[0].AppName} opened an outbound connection to {RemoteSummary(newApps[0])} and has no Block/Allow decision yet. " +
              "This is not a malware verdict and nothing is blocked. Open Firewall to review the connection and decide."
            : $"{newApps.Count} new outbound applications have no Block/Allow decision yet: {names}{suffix}. " +
              "This is not a malware verdict and nothing is blocked. Open Firewall to review them.";

        AxiomAlertService.Show(
            "Axiom Shield decision needed",
            message,
            page: typeof(FirewallPageViewModel),
            focusApps: newApps.Select(app => app.AppPath).ToList());
    }

    private static string RemoteSummary(ProtectionPendingApp app) =>
        app.RemoteEndpoints.Count == 0
            ? "an unreported remote endpoint"
            : string.Join(", ", app.RemoteEndpoints);

    /// <summary>
    /// Selects the page a tray alert points at and highlights the applications it was about.
    /// Called from the alert's Open action or the notification history on the UI thread.
    /// </summary>
    public void NavigateToPage(Type pageViewModelType, IReadOnlyList<string>? focusApps = null)
    {
        ArgumentNullException.ThrowIfNull(pageViewModelType);
        foreach (var page in Pages)
        {
            if (!pageViewModelType.IsInstanceOfType(page))
            {
                continue;
            }

            SelectedPage = page;
            if (focusApps is { Count: > 0 } && page == Firewall)
            {
                Firewall.FocusPendingApps(focusApps);
            }

            return;
        }
    }

    public ObservableCollection<AlertRecord> Alerts => AlertCenter.Items;

    public int UnreadAlertCount => AlertCenter.UnreadCount;

    public bool HasUnreadAlerts => UnreadAlertCount > 0;

    public bool HasAlerts => Alerts.Count > 0;

    [RelayCommand]
    private void MarkAllAlertsRead() => AlertCenter.MarkAllRead();

    [RelayCommand]
    private void ClearAlerts() => AlertCenter.Clear();

    /// <summary>Opens the page an alert belongs to and highlights what it was about.</summary>
    public void OpenAlert(AlertRecord alert)
    {
        ArgumentNullException.ThrowIfNull(alert);
        AlertCenter.MarkRead(alert);
        if (alert.Page is not null)
        {
            NavigateToPage(alert.Page, alert.FocusApps);
        }
    }

    private void OnAlertCenterChanged(object? sender, EventArgs e)
    {
        OnPropertyChanged(nameof(UnreadAlertCount));
        OnPropertyChanged(nameof(HasUnreadAlerts));
        OnPropertyChanged(nameof(HasAlerts));
    }

    private void RefreshStatus()
    {
        StatusMonitoringText = _monitor.LastError is null
            ? $"Monitoring: live · {_monitor.PollInterval.TotalSeconds:0} s · {_monitor.SourceName}"
            : $"Monitoring: unavailable · {_monitor.LastError}";

        StatusSourceText = _protection is { Enabled: true }
            ? OperatingSystem.IsWindows()
                ? "Data source: local service · traffic not filtered"
                : Firewall.Enforcement.IsEnforcementVerified
                    ? $"Data source: local service · Axiom Shield on · {Firewall.Enforcement.VerifiedStatusText}"
                    : "Data source: local service · Axiom Shield on · blocks not verified"
            : IsServiceMode
                ? "Data source: local service (read-only)"
                : "Data source: in-process IP Helper (read-only)";

        if (_protection is { Enabled: true } protection)
        {
            var awaiting = protection.Pending.Count(app => !ShieldProcessFilter.IsIgnored(app.AppPath));
            StatusFirewallText = awaiting > 0
                ? $"Protection: ON · {protection.OwnedRuleCount} rule(s) · {awaiting} awaiting decision"
                : $"Protection: ON · {protection.OwnedRuleCount} rule(s)";
            StatusFirewallBadgeText = "SHIELD ON";
        }
        else if (ServiceStatus?.Capabilities?.FirewallWrites == true)
        {
            StatusFirewallText = "Firewall writes: enabled for this service session";
            StatusFirewallBadgeText = "TEST VM";
        }
        else
        {
            StatusFirewallText = "Protection: off";
            StatusFirewallBadgeText = "READ-ONLY";
        }
        StatusModeText = IsServiceMode ? "Service monitor" : "In-process monitor";

        StatusStorageText = ServiceStatus?.IsConnected == true
            ? "Database: service-managed"
            : "Database: not connected";

        StatusIpcText = ServiceStatus switch
        {
            { IsConnected: true, Capabilities: { } capabilities } =>
                $"IPC: local service · contract v{capabilities.ProtocolVersion}",
            { IsConnected: false } => "IPC: service offline",
            _ => IsServiceMode ? "IPC: probing local service" : "IPC: not connected",
        };

        FooterText = IsServiceMode
            ? "Local service · no driver · no telemetry · no remote access."
            : "In-process monitor · no service · no driver · no telemetry.";
        OnPropertyChanged(nameof(FooterText));
    }

    private async Task ProbeServiceAsync(bool force = false)
    {
        if (_serviceProbe is null || _isProbing)
        {
            return;
        }

        // The monitor ticks every second; probing the pipe at the same rate would double the
        // request load for a status string that rarely changes.
        if (!force && DateTimeOffset.UtcNow - _lastProbeUtc < TimeSpan.FromSeconds(5))
        {
            return;
        }

        _isProbing = true;
        _lastProbeUtc = DateTimeOffset.UtcNow;
        try
        {
            var status = await _serviceProbe.ProbeAsync(_cancellation.Token).ConfigureAwait(true);
            ServiceStatus = status;
            RefreshStatus();
        }
        catch (OperationCanceledException)
        {
            // Shutting down.
        }
        finally
        {
            _isProbing = false;
        }
    }
}
