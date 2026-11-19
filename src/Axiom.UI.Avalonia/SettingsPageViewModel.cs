// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>Appearance, startup and build information. Only per-user settings are written.</summary>
public sealed partial class SettingsPageViewModel : PageViewModel, IDisposable
{
    private readonly IThemeService _theme;
    private readonly IAutostartService _autostart;
    private readonly FirewallPageViewModel? _firewall;
    private readonly IUserInteraction _ui;
    private readonly IVisualEffectsService _visualEffects;
    private readonly Func<CancellationToken, Task<NetworkRecoveryRestoreResult>>? _restoreNetwork;
    private readonly StartupSettingsStore _startupSettings = new();
    private readonly UpdateCheckService _updateChecker;
    private readonly bool _ownsUpdateChecker;
    private bool _updatingStartup;

    public SettingsPageViewModel(
        ConnectionMonitor monitor,
        bool serviceMode,
        IThemeService theme,
        IAutostartService autostart,
        FirewallPageViewModel? firewall = null,
        IUserInteraction? userInteraction = null,
        IVisualEffectsService? visualEffects = null,
        Func<CancellationToken, Task<NetworkRecoveryRestoreResult>>? restoreNetwork = null,
        UpdateCheckService? updateChecker = null)
        : base("Settings", "Appearance, build and license information", "G")
    {
        ArgumentNullException.ThrowIfNull(monitor);
        ArgumentNullException.ThrowIfNull(theme);
        ArgumentNullException.ThrowIfNull(autostart);
        _theme = theme;
        _autostart = autostart;
        _firewall = firewall;
        _ui = userInteraction ?? new NullUserInteraction();
        _visualEffects = visualEffects ?? new FixedVisualEffectsService();
        _restoreNetwork = restoreNetwork;
        _ownsUpdateChecker = updateChecker is null;
        _updateChecker = updateChecker ?? new UpdateCheckService(
            typeof(SettingsPageViewModel).Assembly.GetName().Version ?? new Version(0, 0, 0));

        if (_restoreNetwork is not null)
        {
            NetworkRecoveryStatusText =
                "Restore uses the baseline the Axiom service saved before protection changes.";
        }

        CollectorText = monitor.SourceName;
        PollText = $"{monitor.PollInterval.TotalSeconds:0} s · read-only";
        ProtocolText = serviceMode
            ? $"IPC contract v{IpcProtocol.CurrentVersion} (service connected)"
            : $"IPC contract v{IpcProtocol.CurrentVersion} (not connected)";
        DataModeText = monitor.SourceName.Contains("demo", StringComparison.OrdinalIgnoreCase)
            ? "DEMO — generated rows, no OS telemetry"
            : "LIVE — local socket inventory, no telemetry";

        _theme.Changed += OnThemeChanged;
        CurrentThemeText = ThemeLabel(_theme.Current);
        _visualEffects.Changed += OnVisualEffectsChanged;
        CurrentVisualEffectsText = VisualEffectsText();

        var startup = _startupSettings.Load();
        _updatingStartup = true;
        IsAutostartSupported = autostart.IsSupported;
        StartWithWindows = autostart.IsSupported && autostart.IsEnabled;
        StartMinimized = startup.StartMinimized;
        TrayNotificationsEnabled = TraySettingsStore.Enabled;
        NotificationsEnabled = NotificationSettingsStore.Enabled;
        HideBackgroundWindows = BackgroundWindowSettingsStore.Enabled;
        CheckForUpdates = _updateChecker.CheckForUpdates;
        _updatingStartup = false;
        UpdateStartupStatus();
    }

    public bool IsAutostartSupported { get; }

    public string MilestoneText => OperatingSystem.IsMacOS()
        ? $"{Axiom.Contracts.ProductMilestone.Current} · macOS port"
        : $"{Axiom.Contracts.ProductMilestone.Current} · Windows-first";

    public string ProtocolText { get; }

    public string DataModeText { get; }

    public string CollectorText { get; }

    public string PollText { get; }

    public string StorageText => OperatingSystem.IsMacOS()
        ? "/Library/Application Support/Axiom/axiom.db (daemon)"
        : @"%LOCALAPPDATA%\Axiom\axiom.db (service mode)";

    public string OsText => OperatingSystem.IsMacOS()
        ? "macOS " + Environment.OSVersion.Version.ToString(3)
        : Environment.OSVersion.VersionString;

    public string ProcessText =>
        $"{RuntimeInformation.ProcessArchitecture} · 64-bit process: " +
        $"{(Environment.Is64BitProcess ? "yes" : "no")}";

    public string AppVersion =>
        $"v{typeof(SettingsPageViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"}";

    public string AboutTagline => "Free & open-source network and AI agent security";

    public string AboutCreatedBy => AxiomDocuments.CreatorLabel;

    public string AboutContributors => AxiomDocuments.ContributorsLine;

    /// <summary>Creator credited separately from the wider core team.</summary>
    public ProjectRole AboutFounder => AxiomDocuments.Founder;

    /// <summary>Core maintainers and platform leads shown in About.</summary>
    public IReadOnlyList<ProjectRole> AboutCoreTeam => AxiomDocuments.CoreTeam;

    public string AboutCoreTeamStatement => AxiomDocuments.CoreTeamStatement;

    public string AboutAffiliationLabel => AxiomDocuments.AffiliationLabel;

    public string AboutAffiliation => AxiomDocuments.AffiliationText;

    public string AboutCopyright => AxiomDocuments.CopyrightLine;

    public string AboutLicense => AxiomDocuments.LicenseName;

    /// <summary>One compact legal line: license and collective copyright.</summary>
    public string AboutLegalLine =>
        $"{AxiomDocuments.ShortLicenseName} \u00B7 {AxiomDocuments.CopyrightLine}";

    /// <summary>True when the host supplied a restore operation.</summary>
    public bool HasNetworkRecovery => _restoreNetwork is not null;

    [ObservableProperty]
    private string _networkRecoveryStatusText = string.Empty;

    /// <summary>Restores the saved DNS servers and removes the captured Axiom-owned rules.</summary>
    [RelayCommand]
    private async Task RestoreNetworkSettingsAsync()
    {
        if (_restoreNetwork is null)
        {
            return;
        }

        NetworkRecoveryStatusText = "Restoring the saved network state...";

        try
        {
            var result = await _restoreNetwork(CancellationToken.None).ConfigureAwait(true);
            NetworkRecoveryStatusText = NetworkRecoveryText.DescribeRestore(result);
        }
        catch (OperationCanceledException)
        {
            NetworkRecoveryStatusText = "Restore was cancelled. The result was not verified.";
        }
        catch (Exception exception) when (exception is InvalidOperationException or UnauthorizedAccessException)
        {
            NetworkRecoveryStatusText =
                $"Restore failed before it could complete: {exception.Message}";
        }
    }

    public string AboutSource => AxiomDocuments.SourceUrl;



    [RelayCommand]
    private Task ViewLicenseAsync() =>
        _ui.ShowDocumentAsync(AxiomDocuments.LicenseName, AxiomDocuments.LicenseBundle, CancellationToken.None);

    [RelayCommand]
    private Task ViewThirdPartyNoticesAsync() =>
        _ui.ShowDocumentAsync("Third-party notices", AxiomDocuments.ThirdPartyNotices, CancellationToken.None);

    [RelayCommand]
    private Task ViewContributorsAsync() =>
        _ui.ShowDocumentAsync("Axiom contributors", AxiomDocuments.Authors, CancellationToken.None);

    [RelayCommand]
    private Task OpenSourceAsync() => OpenExternalAsync(AxiomDocuments.SourceUrl, "Source code", "repository");

    [RelayCommand]
    private Task OpenAffiliationAsync() => OpenExternalAsync(AxiomDocuments.AffiliationUrl, "OpenDKG", "website");

    /// <summary>Opens a maintainer's GitHub profile through the existing external-link path.</summary>
    [RelayCommand]
    private Task OpenProfileAsync(string? url) =>
        OpenExternalAsync(
            string.IsNullOrWhiteSpace(url) ? AxiomDocuments.SourceUrl : url,
            "GitHub profile",
            "profile");

    private async Task OpenExternalAsync(string url, string title, string label)
    {
        try
        {
            await _ui.OpenExternalAsync(url, CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is NotSupportedException or InvalidOperationException)
        {
            await _ui.ShowMessageAsync(
                title,
                $"This build cannot open a browser. The {label} is {url}.",
                CancellationToken.None).ConfigureAwait(true);
        }
    }

    [ObservableProperty]
    private string _currentThemeText = "Dark";

    /// <summary>Selected effects level plus the backdrop the host actually reported.</summary>
    [ObservableProperty]
    private string _currentVisualEffectsText = "Visual effects: Auto";

    [ObservableProperty]
    private bool _trayNotificationsEnabled = true;

    [ObservableProperty]
    private bool _notificationsEnabled = true;

    [ObservableProperty]
    private bool _hideBackgroundWindows = true;

    [ObservableProperty]
    private bool _startWithWindows;

    [ObservableProperty]
    private bool _startMinimized;

    [ObservableProperty]
    private bool _checkForUpdates = true;

    [ObservableProperty]
    private string _startupStatusText = "Autostart: off";

    [ObservableProperty]
    private bool _canRepairStartup;

    partial void OnTrayNotificationsEnabledChanged(bool value)
    {
        if (_updatingStartup)
        {
            return;
        }

        TraySettingsStore.SetEnabled(value);
    }

    partial void OnNotificationsEnabledChanged(bool value)
    {
        if (_updatingStartup)
        {
            return;
        }

        NotificationSettingsStore.SetEnabled(value);
    }

    partial void OnHideBackgroundWindowsChanged(bool value)
    {
        if (_updatingStartup)
        {
            return;
        }

        BackgroundWindowSettingsStore.SetEnabled(value);
    }

    partial void OnCheckForUpdatesChanged(bool value)
    {
        if (_updatingStartup)
        {
            return;
        }

        _updateChecker.SetCheckForUpdatesEnabled(value);
    }

    [RelayCommand]
    private void TestNotification()
    {
        // Point the test at a real pending decision so the click can demonstrate the highlight.
        var pending = _firewall?.Pending.FirstOrDefault();
        AxiomAlertService.Show(
            "Axiom alert test",
            pending is null
                ? "This is a test alert. A real Shield alert names the executable, the remote endpoint it contacted and the fact that no Block/Allow decision exists yet. Axiom never blocks automatically."
                : $"Test alert: {pending.AppName} opened an outbound connection to {pending.RemoteSummary} and has no Block/Allow decision yet. This is not a malware verdict and nothing is blocked.",
            force: true,
            page: typeof(FirewallPageViewModel),
            focusApps: pending is null ? null : [pending.AppPath],
            lifetime: TimeSpan.FromSeconds(20));
    }

    partial void OnStartWithWindowsChanged(bool value)
    {
        if (_updatingStartup || !IsAutostartSupported)
        {
            return;
        }

        var success = _autostart.SetEnabled(value);
        if (!success)
        {
            _updatingStartup = true;
            StartWithWindows = _autostart.IsEnabled;
            _updatingStartup = false;
        }

        SaveStartupPreferences();
        UpdateStartupStatus();
    }

    partial void OnStartMinimizedChanged(bool value)
    {
        if (_updatingStartup)
        {
            return;
        }

        SaveStartupPreferences();
    }

    [RelayCommand]
    private void RepairStartup()
    {
        if (!IsAutostartSupported)
        {
            return;
        }

        var success = _autostart.Repair();
        _updatingStartup = true;
        StartWithWindows = success;
        _updatingStartup = false;
        SaveStartupPreferences();
        UpdateStartupStatus();
    }

    public void Dispose()
    {
        _theme.Changed -= OnThemeChanged;
        _visualEffects.Changed -= OnVisualEffectsChanged;
        if (_ownsUpdateChecker)
        {
            _updateChecker.Dispose();
        }
    }

    public bool IsGlassDarkTheme => _theme.Current == UiTheme.GlassDark;

    public bool IsGlassLightTheme => _theme.Current == UiTheme.GlassLight;

    public bool IsDarkTheme => _theme.Current == UiTheme.Dark;

    public bool IsLightTheme => _theme.Current == UiTheme.Light;

    public bool IsDarkMidnightTheme => _theme.Current == UiTheme.DarkMidnight;

    public bool IsLightWarmTheme => _theme.Current == UiTheme.LightWarm;

    public bool IsAutoEffects => _visualEffects.Current == VisualEffects.Auto;

    public bool IsFullEffects => _visualEffects.Current == VisualEffects.Full;

    public bool IsReducedEffects => _visualEffects.Current == VisualEffects.Reduced;

    public bool IsNoEffects => _visualEffects.Current == VisualEffects.Off;

    [RelayCommand]
    private void UseAutoEffects() => _visualEffects.Apply(VisualEffects.Auto);

    [RelayCommand]
    private void UseFullEffects() => _visualEffects.Apply(VisualEffects.Full);

    [RelayCommand]
    private void UseReducedEffects() => _visualEffects.Apply(VisualEffects.Reduced);

    [RelayCommand]
    private void UseNoEffects() => _visualEffects.Apply(VisualEffects.Off);

    private void OnVisualEffectsChanged(object? sender, EventArgs e)
    {
        CurrentVisualEffectsText = VisualEffectsText();
        OnPropertyChanged(nameof(IsAutoEffects));
        OnPropertyChanged(nameof(IsFullEffects));
        OnPropertyChanged(nameof(IsReducedEffects));
        OnPropertyChanged(nameof(IsNoEffects));
    }

    private string VisualEffectsText() =>
        $"Visual effects: {VisualEffectsLabels.Label(_visualEffects.Current)}. " +
        $"Backdrop: {_visualEffects.BackdropStatus}.";

    [RelayCommand]
    private void UseDarkTheme() => _theme.Apply(UiTheme.Dark);

    [RelayCommand]
    private void UseLightTheme() => _theme.Apply(UiTheme.Light);

    [RelayCommand]
    private void UseDarkMidnightTheme() => _theme.Apply(UiTheme.DarkMidnight);

    [RelayCommand]
    private void UseLightWarmTheme() => _theme.Apply(UiTheme.LightWarm);

    [RelayCommand]
    private void UseGlassDarkTheme() => _theme.Apply(UiTheme.GlassDark);

    [RelayCommand]
    private void UseGlassLightTheme() => _theme.Apply(UiTheme.GlassLight);

    private void OnThemeChanged(object? sender, EventArgs e)
    {
        CurrentThemeText = ThemeLabel(_theme.Current);
        OnPropertyChanged(nameof(IsGlassDarkTheme));
        OnPropertyChanged(nameof(IsGlassLightTheme));
        OnPropertyChanged(nameof(IsDarkTheme));
        OnPropertyChanged(nameof(IsLightTheme));
        OnPropertyChanged(nameof(IsDarkMidnightTheme));
        OnPropertyChanged(nameof(IsLightWarmTheme));
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

    private void SaveStartupPreferences() =>
        _startupSettings.Save(new StartupSettings(
            StartWithWindows,
            StartMinimized,
            Environment.ProcessPath ?? string.Empty,
            DateTimeOffset.UtcNow));

    private void UpdateStartupStatus()
    {
        if (!IsAutostartSupported)
        {
            CanRepairStartup = false;
            StartupStatusText = "Autostart: managed by Windows for Store packages";
            return;
        }

        CanRepairStartup = _autostart.CanRepair;
        StartupStatusText = _autostart.StatusText;
    }
}
