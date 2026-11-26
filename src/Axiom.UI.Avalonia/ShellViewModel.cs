// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.IO;
using System.Net.Http;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Contracts;
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
    private readonly IShellActions _shellActions;
    private readonly IThemeService _theme;
    private readonly IUiModeService _uiMode;
    private readonly IVisualEffectsService _visualEffects;
    private readonly UpdateCheckService _updateChecker;
    private readonly bool _ownsUpdateChecker;
    private readonly IUiTimer _updateTimer;
    private readonly IUiTimer _trayProtectionTimer;
    private readonly CancellationTokenSource _cancellation = new();
    private string? _announcedUpdateVersion;
    private DateTimeOffset _lastProbeUtc = DateTimeOffset.MinValue;
    private DateTimeOffset _lastProtectionProbeUtc = DateTimeOffset.MinValue;
    private bool _isProbing;
    private bool _isProbingProtection;
    private readonly ServiceReachabilityClient? _reachability;
    private bool _serviceUnreachable;
    private bool _updatingTheme;
    private bool _disposed;
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
        ILoopbackListenerInspector? listenerInspector = null,
        UpdateCheckService? updateChecker = null,
        IUiModeService? uiModeService = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(timers);
        _monitor = new ConnectionMonitor(source, timers);
        _traffic = new TrafficEngine(timers);
        _serviceProbe = serviceProbe;
        if (!OperatingSystem.IsWindows() && serviceClient is not null)
        {
            // One shared reachability signal: every page's service call reports through it.
            _reachability = new ServiceReachabilityClient(serviceClient);
            serviceClient = _reachability;
        }

        _serviceClient = serviceClient;
        IsServiceMode = source is ServiceSnapshotSource;
        var interaction = userInteraction ?? new NullUserInteraction();
        _ui = interaction;
        _shellActions = shellActions ?? new UnsupportedShellActions();
        _theme = themeService ?? new FixedThemeService();
        _uiMode = uiModeService ?? new FixedUiModeService();
        _visualEffects = visualEffects ?? new FixedVisualEffectsService();
        _ownsUpdateChecker = updateChecker is null;
        _updateChecker = updateChecker ?? new UpdateCheckService(
            typeof(ShellViewModel).Assembly.GetName().Version ?? new Version(0, 0, 0));
        _updateTimer = timers.Create(UpdateCheckService.MinimumCheckInterval);
        _trayProtectionTimer = timers.Create(TimeSpan.FromSeconds(30));
        var processes = processActions ?? new UnsupportedProcessActions();
        PrivacyShield = new PrivacyShieldPageViewModel(
            IsServiceMode ? serviceClient : null,
            interaction,
            dnsAdapterHelper ?? new UnsupportedDnsAdapterHelper(),
            timers);
        PrivacyOverview = new PrivacyOverviewPageViewModel(
            PrivacyShield,
            openSettings: () => NavigateContextual(PrivacyShield),
            traderShield: new TraderShieldSectionViewModel());
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
            processes,
            startActive: false);
        Overview = new OverviewPageViewModel(
            _monitor,
            _traffic,
            interaction,
            IsServiceMode ? serviceClient : null,
            processes,
            PrivacyShield,
            openPrivacyOverview: () => SelectedPage = PrivacyOverview,
            openPrivacySettings: () => SelectedPage = PrivacyShield,
            connectionsTab: Connections,
            appsTab: Apps,
            eventsTab: Events,
            timers: timers);
        Firewall = new FirewallPageViewModel(IsServiceMode ? serviceClient : null, interaction, _monitor);
        if (_serviceClient is null)
        {
            // No service to ask: the shield is simply unavailable (off), not unknown.
            Firewall.ProtectionKnown = true;
        }

        // "Check protection" re-reads through the shell probe, so every surface takes the same answer.
        Firewall.RecheckProtection = () => ProbeProtectionAsync(force: true);
        Firewall.PropertyChanged += OnFirewallStateChanged;
        // Review #25: the Overview line follows the same state as the "SHIELD ON" badge.
        Overview.ProtectionState = () => new OverviewProtectionState(
            // The service-reported write gate, not the UI toggle: Shield on does not imply writes.
            FirewallWritesEnabled: _protection?.WriteGateOpen == true,
            FirewallProtectionActive: _protection is { Enabled: true },
            PrivacyShieldActive: PrivacyShield.IsResolverActive,
            Enforcement: OperatingSystem.IsWindows() ? null : Firewall.Enforcement);
        Security = new SecurityPageViewModel(
            interaction,
            securityDialogs ?? new UnsupportedSecurityDialogs(),
            apiKeyProtector ?? new UnsupportedApiKeyProtector(),
            timers,
            _shellActions,
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
            restoreNetwork,
            _updateChecker);
        AgentStats = new AgentStatsPageViewModel(Agents);
        AgentDashboard = new AgentDashboardPageViewModel(Agents);
        AgentHealth = new AgentHealthPageViewModel(Agents, Security);
        SimpleHome = new SimpleHomePageViewModel(
            Overview,
            Firewall,
            PrivacyShield,
            Agents,
            openFirewall: () => SelectedPage = Firewall,
            openPrivacyOverview: () => SelectedPage = PrivacyOverview,
            openNetworkAdvanced: () => NavigateContextual(Overview),
            switchToAdvanced: () => _uiMode.Apply(UiMode.Advanced),
            openAgentsAdvanced: () => NavigateContextual(Agents));
        MiniHome = new MiniHomePageViewModel(
            Overview,
            Firewall,
            PrivacyShield,
            Agents,
            VersionText,
            openNetworkOverview: () => NavigateContextual(Overview),
            openPrivacy: () =>
            {
                _uiMode.Apply(UiMode.Simple);
                SelectedPage = PrivacyOverview;
            },
            openAgents: () => NavigateContextual(Agents),
            openSettings: () =>
            {
                _uiMode.Apply(UiMode.Simple);
                SelectedPage = Settings;
            },
            openSupport: () =>
            {
                _uiMode.Apply(UiMode.Simple);
                SelectedPage = Support;
            },
            openWebsite: () => OpenWebsiteCommand.Execute(null),
            openGitHub: OpenGitHubAsync,
            expandView: () => _uiMode.Apply(UiMode.Advanced));
        Pages =
        [
            AgentDashboard,
            Overview,
            PrivacyOverview,
            Agents,
            AgentStats,
            AgentHealth,
            AiAnalyst,
            Firewall,
            PrivacyShield,
            Security,
            Settings,
            Support,
        ];

        ApplyNavigationMode(_uiMode.Current, initialSetup: true);
        _selectedPage = NavigationPages[0];
        _activePage = NavigationPages[0];
        _selectedTheme = ThemeLabel(_theme.Current);
        _theme.Changed += OnThemeChanged;
        _uiMode.Changed += OnUiModeChanged;
        _monitor.Updated += OnMonitorUpdated;
        if (_reachability is not null)
        {
            _reachability.Answered += OnServiceAnswered;
            _reachability.Unreachable += OnServiceUnreachable;
            Firewall.ProtectionStatusApplied += OnFirewallProtectionApplied;
        }

        AlertCenter.Changed += OnAlertCenterChanged;
        _updateChecker.Changed += OnUpdateCheckerChanged;
        _updateTimer.Tick += OnUpdateTimerTick;
        _trayProtectionTimer.Tick += OnTrayProtectionTimerTick;
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
    private Task OpenGitHubAsync() =>
        OpenExternalUrlAsync(ProjectLinks.Repository);

    [RelayCommand]
    private Task OpenContactAsync() =>
        OpenExternalUrlAsync("mailto:contact@opendkg.org");

    [RelayCommand]
    private Task OpenWebsiteAsync() =>
        OpenExternalUrlAsync(ProjectLinks.Website);

    [RelayCommand]
    private void OpenSupport()
    {
        if (IsMiniMode)
        {
            _uiMode.Apply(UiMode.Simple);
        }

        SelectedPage = Support;
    }

    public bool UpdateAvailable => _updateChecker.IsUpdateAvailable;

    public string LatestVersion => _updateChecker.LatestVersion;

    public string UpdateTooltip => UpdateAvailable
        ? $"Update to version {LatestVersion}"
        : string.Empty;

    public string UpdateReleaseDateText => _updateChecker.ReleaseDateText;

    public string UpdateSummaryText => _updateChecker.SummaryText;

    public string UpdateReleaseNotesText => !string.IsNullOrWhiteSpace(_updateChecker.ReleaseNotesText)
        ? _updateChecker.ReleaseNotesText
        : _updateChecker.SummaryText;

    public bool HasUpdateReleaseDate => !string.IsNullOrWhiteSpace(UpdateReleaseDateText);

    public bool HasUpdateSummary => !string.IsNullOrWhiteSpace(UpdateSummaryText);

    public bool HasUpdateReleaseNotes => !string.IsNullOrWhiteSpace(UpdateReleaseNotesText);

    [RelayCommand]
    private Task OpenReleasePageAsync() => OpenExternalUrlAsync(_updateChecker.ReleaseUrl);

    public string UpdateActionText => _updateChecker.HasDirectInstaller ? "Update now" : "View release";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasUpdateDownloadStatus))]
    private string _updateDownloadStatus = string.Empty;

    public bool HasUpdateDownloadStatus => !string.IsNullOrWhiteSpace(UpdateDownloadStatus);

    [ObservableProperty]
    private bool _isDownloadingUpdate;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsUpdateDownloadIndeterminate))]
    private int _updateDownloadProgress;

    public bool IsUpdateDownloadIndeterminate => UpdateDownloadProgress == 0;

    [RelayCommand]
    private async Task OpenUpdateAsync()
    {
        if (IsDownloadingUpdate)
        {
            return;
        }

        if (!_updateChecker.HasDirectInstaller)
        {
            await OpenExternalUrlAsync(_updateChecker.ReleaseUrl).ConfigureAwait(true);
            return;
        }

        var token = _cancellation.Token;
        UpdateDownloadProgress = 0;
        IsDownloadingUpdate = true;
        UpdateDownloadStatus = "Downloading Axiom update…";
        var progress = new Progress<int>(percent =>
        {
            if (!IsDownloadingUpdate)
            {
                return;
            }

            UpdateDownloadProgress = percent;
            if (percent == 100)
            {
                UpdateDownloadStatus = "Verifying package integrity…";
            }
        });
        try
        {
            var installer = await _updateChecker.DownloadPlatformInstallerAsync(token, progress).ConfigureAwait(true);
            token.ThrowIfCancellationRequested();
            await _ui.OpenExternalAsync(installer, token).ConfigureAwait(true);
            if (OperatingSystem.IsWindows())
            {
                UpdateDownloadStatus = "Starting installer — Axiom is closing to complete the update…";
                _shellActions.Shutdown();
            }
            else if (OperatingSystem.IsLinux())
            {
                UpdateDownloadStatus = "Package verified and opened. Confirm the installer prompt to complete the update.";
            }
            else
            {
                UpdateDownloadStatus = "Update archive verified and opened. Move Axiom.app into Applications to finish updating.";
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        catch (OperationCanceledException)
        {
            UpdateDownloadStatus = "Download timed out. Please try again in a moment.";
        }
        catch (Exception exception) when (exception is
                     IOException or HttpRequestException or UnauthorizedAccessException or
                     InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
        {
            UpdateDownloadStatus = $"Could not start the update: {exception.Message}";
        }
        finally
        {
            IsDownloadingUpdate = false;
        }
    }

    private async Task OpenExternalUrlAsync(string url)
    {
        try
        {
            await _ui.OpenExternalAsync(url, CancellationToken.None)
                .ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is
                     InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
        {
            // No browser handler is available; leave the shell usable.
        }
    }

    [RelayCommand]
    private void DismissUpdate() => _updateChecker.Dismiss();

    /// <summary>Runs a silent update check if opted in and the 30-minute cooldown has elapsed.</summary>
    public async Task<bool> CheckForUpdatesAsync()
    {
        if (_disposed)
        {
            return false;
        }

        var token = _cancellation.Token;
        try
        {
            return await _updateChecker.CheckIfDueAsync(token).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (_disposed || token.IsCancellationRequested)
        {
            return false;
        }
    }

    private async Task<bool> CheckForUpdatesOnStartupAsync()
    {
        if (_disposed)
        {
            return false;
        }

        var token = _cancellation.Token;
        try
        {
            return await _updateChecker.CheckOnStartupAsync(token).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (_disposed || token.IsCancellationRequested)
        {
            return false;
        }
    }

    private void OnUpdateTimerTick(object? sender, EventArgs e) =>
        _ = CheckForUpdatesAsync();

    private void OnTrayProtectionTimerTick(object? sender, EventArgs e)
    {
        if (!_presentationVisible && !_disposed)
        {
            _ = ProbeProtectionAsync(force: true);
        }
    }

    private void OnUpdateCheckerChanged(object? sender, EventArgs e)
    {
        if (global::Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
        {
            RaiseUpdatePropertiesChanged();
        }
        else
        {
            global::Avalonia.Threading.Dispatcher.UIThread.Post(RaiseUpdatePropertiesChanged);
        }
    }

    private void RaiseUpdatePropertiesChanged()
    {
        OnPropertyChanged(nameof(UpdateAvailable));
        OnPropertyChanged(nameof(LatestVersion));
        OnPropertyChanged(nameof(UpdateTooltip));
        OnPropertyChanged(nameof(UpdateActionText));
        OnPropertyChanged(nameof(UpdateReleaseDateText));
        OnPropertyChanged(nameof(UpdateSummaryText));
        OnPropertyChanged(nameof(UpdateReleaseNotesText));
        OnPropertyChanged(nameof(HasUpdateReleaseDate));
        OnPropertyChanged(nameof(HasUpdateSummary));
        OnPropertyChanged(nameof(HasUpdateReleaseNotes));

        if (_updateChecker.IsUpdateAvailable &&
            !string.IsNullOrWhiteSpace(_updateChecker.LatestVersion) &&
            !string.Equals(_announcedUpdateVersion, _updateChecker.LatestVersion, StringComparison.OrdinalIgnoreCase))
        {
            _announcedUpdateVersion = _updateChecker.LatestVersion;
            AxiomAlertService.Show(
                "Update available",
                $"Axiom v{_updateChecker.LatestVersion} is ready to install. Click the update icon in the top bar whenever convenient.",
                page: typeof(SettingsPageViewModel));
        }
    }

    public UiMode CurrentUiMode => _uiMode.Current;

    public bool IsMiniMode => _uiMode.Current == UiMode.Mini;

    public bool IsSimpleMode => _uiMode.Current == UiMode.Simple;

    public bool IsAdvancedMode => _uiMode.Current == UiMode.Advanced;

    [RelayCommand]
    private void SwitchToMiniMode() => _uiMode.Apply(UiMode.Mini);

    [RelayCommand]
    private void SwitchToSimpleMode() => _uiMode.Apply(UiMode.Simple);

    [RelayCommand]
    private void SwitchToAdvancedMode() => _uiMode.Apply(UiMode.Advanced);

    private void OnUiModeChanged(object? sender, EventArgs e)
    {
        ApplyNavigationMode(_uiMode.Current, initialSetup: false);
        OnPropertyChanged(nameof(CurrentUiMode));
        OnPropertyChanged(nameof(IsMiniMode));
        OnPropertyChanged(nameof(IsSimpleMode));
        OnPropertyChanged(nameof(IsAdvancedMode));
    }

    private void ApplyNavigationMode(UiMode mode, bool initialSetup)
    {
        var previous = initialSetup ? null : SelectedPage;

        foreach (var page in Pages)
        {
            page.GroupLabel = null;
        }
        SimpleHome.GroupLabel = null;
        MiniHome.GroupLabel = null;

        _contextualReturnPage = null;
        NavigationPages.Clear();
        if (mode == UiMode.Mini)
        {
            NavigationPages.Add(MiniHome);
        }
        else if (mode == UiMode.Simple)
        {
            SimpleHome.GroupLabel = "HOME";
            Firewall.GroupLabel = "PROTECTION";
            Settings.GroupLabel = "GENERAL";
            NavigationPages.Add(SimpleHome);
            NavigationPages.Add(Firewall);
            NavigationPages.Add(PrivacyOverview);
            NavigationPages.Add(Settings);
            NavigationPages.Add(Support);
        }
        else
        {
            AgentDashboard.GroupLabel = "OVERVIEW";
            Agents.GroupLabel = "AI";
            Firewall.GroupLabel = "NETWORK & PRIVACY";
            Settings.GroupLabel = "GENERAL";
            foreach (var page in Pages)
            {
                NavigationPages.Add(page);
            }
        }

        if (!initialSetup && (previous is null || !NavigationPages.Contains(previous)))
        {
            SelectedPage = NavigationPages[0];
        }

        _lastNavigationPage = NavigationPages.Contains(SelectedPage) ? SelectedPage : NavigationPages[0];
        RaiseNavigationStateChanged();
    }

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

    public MiniHomePageViewModel MiniHome { get; }

    public SimpleHomePageViewModel SimpleHome { get; }

    public AgentDashboardPageViewModel AgentDashboard { get; }

    public OverviewPageViewModel Overview { get; }

    public PrivacyOverviewPageViewModel PrivacyOverview { get; }

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

    public ObservableCollection<PageViewModel> NavigationPages { get; } = [];

    [ObservableProperty]
    private PageViewModel _selectedPage;

    partial void OnSelectedPageChanged(PageViewModel value)
    {
        if (NavigationPages.Contains(value))
        {
            _lastNavigationPage = value;
            _contextualReturnPage = null;
        }

        OnPropertyChanged(nameof(SelectedNavigationPage));
        OnPropertyChanged(nameof(HasContextualReturn));
        OnPropertyChanged(nameof(ContextualReturnText));

        if (_presentationVisible)
        {
            (_activePage as IActivatablePage)?.Deactivate();
            (value as IActivatablePage)?.Activate();
        }

        _activePage = value;
    }

    private PageViewModel? _activePage;
    private PageViewModel? _contextualReturnPage;
    private PageViewModel? _lastNavigationPage;
    private bool _presentationVisible = true;

    /// <summary>True while a Simple/Mini surface shows a page outside its sidebar.</summary>
    public bool HasContextualReturn => _contextualReturnPage is not null;

    /// <summary>Label for the contextual back control.</summary>
    public string ContextualReturnText =>
        _contextualReturnPage is null ? string.Empty : $"Back to {_contextualReturnPage.Title}";

    /// <summary>
    /// Sidebar selection. A contextual sub-page keeps its parent section highlighted instead of
    /// clearing the ListBox selection.
    /// </summary>
    public PageViewModel? SelectedNavigationPage
    {
        get => NavigationPages.Contains(SelectedPage) ? SelectedPage : _lastNavigationPage;
        set
        {
            if (value is not null && !ReferenceEquals(value, SelectedPage))
            {
                SelectedPage = value;
            }
        }
    }

    /// <summary>
    /// Opens a page without persisting a different UI mode. When the page is not in the current
    /// sidebar the previous page is offered as a direct return path.
    /// </summary>
    private void NavigateContextual(PageViewModel page)
    {
        ArgumentNullException.ThrowIfNull(page);
        if (NavigationPages.Contains(SelectedPage))
        {
            _lastNavigationPage = SelectedPage;
        }

        _contextualReturnPage = NavigationPages.Contains(page) ? null : _lastNavigationPage ?? SelectedPage;
        SelectedPage = page;
        RaiseNavigationStateChanged();
    }

    [RelayCommand]
    private void GoBack()
    {
        var target = _contextualReturnPage;
        _contextualReturnPage = null;
        if (target is not null)
        {
            SelectedPage = target;
        }

        RaiseNavigationStateChanged();
    }

    private void RaiseNavigationStateChanged()
    {
        OnPropertyChanged(nameof(HasContextualReturn));
        OnPropertyChanged(nameof(ContextualReturnText));
        OnPropertyChanged(nameof(SelectedNavigationPage));
    }

    public void SetPresentationVisible(bool visible)
    {
        if (_presentationVisible == visible)
        {
            return;
        }

        _presentationVisible = visible;
        if (visible)
        {
            _trayProtectionTimer.StopTimer();
            _monitor.Start();
            Agents.SetTrayMonitoring(false);
            _traffic.Start();
            (_activePage as IActivatablePage)?.Activate();
            RefreshStatus();
            _ = CheckForUpdatesAsync();
        }
        else
        {
            Agents.SetTrayMonitoring(
                ReferenceEquals(_activePage, Agents) ||
                _activePage is AgentDashboardPageViewModel or AgentStatsPageViewModel or
                    AgentHealthPageViewModel or SimpleHomePageViewModel or MiniHomePageViewModel);
            (_activePage as IActivatablePage)?.Deactivate();
            _traffic.Stop();
            _monitor.Stop();
            _trayProtectionTimer.Start();
        }

        Security.SetPresentationVisible(visible);
    }

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

    /// <summary>Neutral lamp colour while the service has not reported the protection state.</summary>
    internal const string UnknownLampColor = ShieldProtection.UnknownColor;

    /// <summary>Amber lamp: shield on, but the network filter has not verified the rules (non-Windows).</summary>
    internal const string UnverifiedLampColor = ShieldProtection.DegradedColor;

    [ObservableProperty]
    private IBrush _statusFirewallBadgeBrush = new SolidColorBrush(Color.Parse("#FB7185"));

    public bool IsServiceMode { get; }

    public ServiceStatusSnapshot? ServiceStatus { get; private set; }

    public string VersionText =>
        $"v{typeof(ShellViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"}";

    public void Start()
    {
        if (_presentationVisible)
        {
            _monitor.Start();
            _traffic.Start();
        }
        else
        {
            _trayProtectionTimer.Start();
        }

        Overview.Refresh();
        if (!ReferenceEquals(SimpleHome, SelectedPage))
        {
            (SimpleHome as IActivatablePage).Deactivate();
        }
        foreach (var page in Pages)
        {
            if (!ReferenceEquals(page, SelectedPage))
            {
                (page as IActivatablePage)?.Deactivate();
            }
        }

        _activePage = SelectedPage;
        if (_presentationVisible)
        {
            (SelectedPage as IActivatablePage)?.Activate();
        }
        RefreshStatus();
        _updateTimer.Start();
        _ = ProbeServiceAsync(force: true);
        _ = CheckForUpdatesOnStartupAsync();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _updateTimer.StopTimer();
        _updateTimer.Tick -= OnUpdateTimerTick;
        _trayProtectionTimer.StopTimer();
        _trayProtectionTimer.Tick -= OnTrayProtectionTimerTick;
        _updateChecker.Changed -= OnUpdateCheckerChanged;
        _monitor.Updated -= OnMonitorUpdated;
        if (_reachability is not null)
        {
            _reachability.Answered -= OnServiceAnswered;
            _reachability.Unreachable -= OnServiceUnreachable;
            Firewall.ProtectionStatusApplied -= OnFirewallProtectionApplied;
        }

        Firewall.PropertyChanged -= OnFirewallStateChanged;
        _theme.Changed -= OnThemeChanged;
        _uiMode.Changed -= OnUiModeChanged;
        AlertCenter.Changed -= OnAlertCenterChanged;
        _cancellation.Cancel();
        _cancellation.Dispose();
        if (_ownsUpdateChecker)
        {
            _updateChecker.Dispose();
        }
        MiniHome.Dispose();
        SimpleHome.Dispose();
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
        if (_disposed)
        {
            return;
        }

        if (_reachability is not null && IsServiceMode)
        {
            // In service mode the monitor reads the same daemon: a transport failure there is
            // the same "unreachable" as any other call; an error the daemon answered is not.
            if (_monitor.LastException is null)
            {
                OnServiceAnswered(this, EventArgs.Empty);
            }
            else if (_monitor.LastException is not ServiceUnavailableException { ServiceResponded: true })
            {
                MarkServiceUnreachable();
            }
        }

        if (_presentationVisible)
        {
            RefreshStatus();
        }

        _ = ProbeServiceAsync();
        _ = ProbeProtectionAsync();
    }

    /// <summary>
    /// Off Windows the header (Overview.StatusText) and the footer read the filter enforcement
    /// summary that Network Control re-reads on its own schedule. Re-render them in the same
    /// update as the page, so the three never state two different answers (the page saying
    /// "generation N verified" while the header still says it is not acknowledged).
    /// </summary>
    private void OnFirewallStateChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        if (e.PropertyName is nameof(FirewallPageViewModel.Enforcement) or nameof(FirewallPageViewModel.ProtectionKnown))
        {
            RefreshStatus();
        }
    }

    /// <summary>
    /// Off Windows: the first service call (from any page, the monitor or a probe) that cannot
    /// reach the daemon turns the header, footer lamp, Network Control, Simple home and Mini to
    /// unknown together, without waiting for each page's own poll (maintainer ruling: unreachable
    /// is unknown, never protected).
    /// </summary>
    private void OnServiceUnreachable(object? sender, EventArgs e)
    {
        if (global::Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
        {
            MarkServiceUnreachable();
        }
        else
        {
            global::Avalonia.Threading.Dispatcher.UIThread.Post(MarkServiceUnreachable);
        }
    }

    private void MarkServiceUnreachable()
    {
        if (_reachability is null)
        {
            return;
        }

        if (_serviceUnreachable && _protection is null && !Firewall.ProtectionKnown)
        {
            return; // Already unknown everywhere; do not rebuild the rows on every failed tick.
        }

        _serviceUnreachable = true;
        _protection = null;
        Firewall.ApplyProtectionUnavailable("Protection status unknown: the local service did not answer.");
        RefreshStatus();
    }

    /// <summary>
    /// The first answer after the daemon was unreachable: an older "offline" probe result no
    /// longer describes it, and the shell re-reads status at once so the header, the footer and
    /// the pages return from the same answer instead of one probe interval apart.
    /// </summary>
    private void OnServiceAnswered(object? sender, EventArgs e)
    {
        if (global::Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
        {
            HandleServiceAnswered();
        }
        else
        {
            global::Avalonia.Threading.Dispatcher.UIThread.Post(HandleServiceAnswered);
        }
    }

    private void HandleServiceAnswered()
    {
        if (!_serviceUnreachable)
        {
            return;
        }

        _serviceUnreachable = false;
        if (ServiceStatus is { IsConnected: false })
        {
            ServiceStatus = null;
        }

        RefreshStatus();
        _ = ProbeServiceAsync(force: true);
        _ = ProbeProtectionAsync(force: true);
    }

    /// <summary>A protection answer read by Network Control itself feeds the header and footer too.</summary>
    private void OnFirewallProtectionApplied(object? sender, ProtectionStatus status)
    {
        _serviceUnreachable = false;
        _protection = status;
        RefreshStatus();
    }

    internal async Task ProbeProtectionAsync(bool force = false)
    {
        if (_disposed || _serviceClient is null || _isProbingProtection)
        {
            return;
        }

        if (!force && DateTimeOffset.UtcNow - _lastProtectionProbeUtc < TimeSpan.FromSeconds(5))
        {
            return;
        }

        _isProbingProtection = true;
        _lastProtectionProbeUtc = DateTimeOffset.UtcNow;
        var token = _cancellation.Token;

        try
        {
            var protection = await _serviceClient
                .SendAsync<ProtectionStatus>(IpcCommandTypes.ProtectionStatus, null, token)
                .ConfigureAwait(true);
            if (_disposed)
            {
                return;
            }

            _protection = protection;
            RefreshStatus();
            NotifyNewPendingApps(_protection);
            // The Home page and the global header read the same service authority; the cache must
            // be fed even when another page is selected, or a change made by another client sticks.
            if (_protection is not null)
            {
                Firewall.UpdateProtectionStatus(_protection);
            }

            // Re-read the lamp after the shield/enforcement state was applied above.
            RefreshStatus();
        }
        catch (ServiceUnavailableException)
        {
            _protection = null;
            Firewall.ApplyProtectionUnavailable("Protection status unknown: the local service did not answer.");
            RefreshStatus();
        }
#pragma warning disable CA1031 // An older service build simply does not expose the shield yet.
        catch (Exception)
#pragma warning restore CA1031
        {
            _protection = null;
            Firewall.ApplyProtectionUnavailable("Protection status unknown: the local service did not answer.");
            RefreshStatus();
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
            _notifiedPendingApps.Clear();
            return;
        }

        var pending = protection.Pending
            .Where(app => !ShieldProcessFilter.IsIgnored(app.AppPath))
            .ToList();
        if (pending.Count == 0)
        {
            _notifiedPendingApps.Clear();
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
        if (pageViewModelType == typeof(MiniHomePageViewModel))
        {
            SelectedPage = MiniHome;
            return;
        }

        if (pageViewModelType == typeof(SimpleHomePageViewModel))
        {
            SelectedPage = SimpleHome;
            return;
        }

        if (pageViewModelType == typeof(ConnectionsPageViewModel))
        {
            _uiMode.Apply(UiMode.Advanced);
            Overview.SelectedMonitoringTabIndex = 0;
            SelectedPage = Overview;
            return;
        }

        if (pageViewModelType == typeof(AppsPageViewModel))
        {
            _uiMode.Apply(UiMode.Advanced);
            Overview.SelectedMonitoringTabIndex = 1;
            SelectedPage = Overview;
            return;
        }

        if (pageViewModelType == typeof(EventsPageViewModel))
        {
            _uiMode.Apply(UiMode.Advanced);
            Overview.SelectedMonitoringTabIndex = 2;
            SelectedPage = Overview;
            return;
        }

        foreach (var page in Pages)
        {
            if (!pageViewModelType.IsInstanceOfType(page))
            {
                continue;
            }

            if (!NavigationPages.Contains(page))
            {
                _uiMode.Apply(UiMode.Advanced);
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

        if (IsServiceMode && (ServiceStatus is { IsConnected: false } || _protection is null))
        {
            // A disconnected or unread service cannot confirm whether protection is active.
            StatusFirewallText = "Protection: unknown · the local service did not answer";
            StatusFirewallBadgeText = "UNKNOWN";
            StatusFirewallBadgeBrush = new SolidColorBrush(Color.Parse(ShieldProtection.LampColor(null)));
        }
        else if (_protection is { Enabled: true } protection)
        {
            var awaiting = protection.Pending.Count(app => !ShieldProcessFilter.IsIgnored(app.AppPath));
            // Off Windows the count follows the daemon's rules.query answer; none while unknown.
            var rules = Firewall.ShieldRuleCount(protection.OwnedRuleCount) is { } count
                ? $" · {count} rule(s)"
                : string.Empty;
            StatusFirewallText = awaiting > 0
                ? $"Protection: ON{rules} · {awaiting} awaiting decision"
                : $"Protection: ON{rules}";
            StatusFirewallBadgeText = "SHIELD ON";
            // Shield on is green only when the platform filter proved enforcement (Windows: not
            // reported, upstream green); otherwise the Degraded tone, never a verified-looking lamp.
            var level = ShieldProtection.Level(
                known: true,
                enabled: true,
                OperatingSystem.IsWindows() ? null : Firewall.Enforcement.IsEnforcementVerified);
            if (level == EnforcementLevel.Degraded)
            {
                StatusFirewallText += " · blocks not verified";
            }

            StatusFirewallBadgeBrush = new SolidColorBrush(Color.Parse(ShieldProtection.LampColor(level)));
        }
        else if (ServiceStatus?.Capabilities?.FirewallWrites == true)
        {
            StatusFirewallText = "Firewall writes: enabled for this service session";
            StatusFirewallBadgeText = "WRITES ON";
            StatusFirewallBadgeBrush = new SolidColorBrush(Color.Parse("#FBBF24"));
        }
        else
        {
            StatusFirewallText = "Protection: off";
            StatusFirewallBadgeText = "READ-ONLY";
            StatusFirewallBadgeBrush = new SolidColorBrush(Color.Parse("#FB7185"));
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
        RefreshHeaderStatus();
    }

    /// <summary>
    /// The global header is bound to Overview.StatusText while other pages are shown. Update that
    /// one line from the service authority without activating the dashboard or its polling.
    /// </summary>
    private void RefreshHeaderStatus()
    {
        if (_monitor.LastError is not null)
        {
            // Off Windows the monitor reads the same daemon: when the protection state is not
            // known either, the header says so first, not only that the monitor is unavailable.
            Overview.SetHeaderStatus(!OperatingSystem.IsWindows() && IsServiceMode && _protection is null
                ? $"Protection status unknown: the local service did not answer. Monitor unavailable: {_monitor.LastError}"
                : $"Monitor unavailable: {_monitor.LastError}");
            return;
        }

        if (_serviceUnreachable)
        {
            // Same signal as the footer lamp and the pages (off Windows only; see the client wrapper).
            Overview.SetHeaderStatus("Protection status unknown: the local service did not answer.");
            return;
        }

        if (IsServiceMode && ServiceStatus is { IsConnected: false })
        {
            Overview.SetHeaderStatus("Protection status unknown: the local service is offline.");
            return;
        }

        if (IsServiceMode && _protection is null)
        {
            Overview.SetHeaderStatus("Protection status unknown: waiting for the local service.");
            return;
        }

        Overview.SetHeaderStatus(OverviewPageViewModel.ComposeStatus(Overview.ProtectionState?.Invoke()));
    }

    private async Task ProbeServiceAsync(bool force = false)
    {
        if (_disposed || _serviceProbe is null || _isProbing)
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
        var token = _cancellation.Token;
        try
        {
            var status = await _serviceProbe.ProbeAsync(token).ConfigureAwait(true);
            if (_disposed)
            {
                return;
            }

            if (_reachability is not null && IsServiceMode && !status.IsConnected)
            {
                // Off Windows the probe's failure joins the shared reachability signal. An error the
                // daemon itself answered (a command an older build lacks) means it is reachable: it
                // is not "offline", so the earlier status line stays and nothing turns unknown.
                if (status.ServiceResponded)
                {
                    OnServiceAnswered(this, EventArgs.Empty);
                    RefreshStatus();
                    return;
                }

                ServiceStatus = status;
                MarkServiceUnreachable();
                RefreshStatus();
                return;
            }

            ServiceStatus = status;
            RefreshStatus();
        }
        catch (OperationCanceledException) when (_disposed || token.IsCancellationRequested)
        {
            // Shutting down.
        }
        finally
        {
            _isProbing = false;
        }
    }
}
