// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Axiom.Contracts.Ipc;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>Appearance, startup and build information. Only per-user settings are written.</summary>
public sealed partial class SettingsPageViewModel : PageViewModel, IDisposable
{
    private readonly IThemeService _theme;
    private readonly IAutostartService _autostart;
    private readonly FirewallPageViewModel? _firewall;
    private readonly IUserInteraction _ui;
    private readonly StartupSettingsStore _startupSettings = new();
    private bool _updatingStartup;

    public SettingsPageViewModel(
        ConnectionMonitor monitor,
        bool serviceMode,
        IThemeService theme,
        IAutostartService autostart,
        FirewallPageViewModel? firewall = null,
        IUserInteraction? userInteraction = null)
        : base("Settings", "Appearance, build and license information", "G")
    {
        ArgumentNullException.ThrowIfNull(monitor);
        ArgumentNullException.ThrowIfNull(theme);
        ArgumentNullException.ThrowIfNull(autostart);
        _theme = theme;
        _autostart = autostart;
        _firewall = firewall;
        _ui = userInteraction ?? new NullUserInteraction();

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

        var startup = _startupSettings.Load();
        _updatingStartup = true;
        IsAutostartSupported = autostart.IsSupported;
        StartWithWindows = autostart.IsSupported && autostart.IsEnabled;
        StartMinimized = startup.StartMinimized;
        TrayNotificationsEnabled = TraySettingsStore.Enabled;
        NotificationsEnabled = NotificationSettingsStore.Enabled;
        HideBackgroundWindows = BackgroundWindowSettingsStore.Enabled;
        _updatingStartup = false;
        UpdateStartupStatus();
    }

    public bool IsAutostartSupported { get; }

    public string MilestoneText => "Avalonia UI migration · Windows-first";

    public string ProtocolText { get; }

    public string DataModeText { get; }

    public string CollectorText { get; }

    public string PollText { get; }

    public string StorageText => @"%LOCALAPPDATA%\Axiom\axiom.db (service mode)";

    public string OsText => Environment.OSVersion.VersionString;

    public string ProcessText =>
        $"{RuntimeInformation.ProcessArchitecture} · 64-bit process: " +
        $"{(Environment.Is64BitProcess ? "yes" : "no")}";

    public string AppVersion =>
        $"v{typeof(SettingsPageViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"}";

    public string AboutTagline => "Free & open-source network and AI agent security";

    public string AboutCreatedBy => AxiomDocuments.CreatorLabel;

    public string AboutContributors => AxiomDocuments.ContributorsLine;

    public string AboutAffiliation => AxiomDocuments.AffiliationText;

    public string AboutCopyright => AxiomDocuments.CopyrightLine;

    public string AboutLicense => AxiomDocuments.LicenseName;

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
    private async Task OpenSourceAsync()
    {
        try
        {
            await _ui.OpenExternalAsync(AxiomDocuments.SourceUrl, CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is NotSupportedException or InvalidOperationException)
        {
            await _ui.ShowMessageAsync(
                "Source code",
                $"This build cannot open a browser. The repository is {AxiomDocuments.SourceUrl}.",
                CancellationToken.None).ConfigureAwait(true);
        }
    }

    [ObservableProperty]
    private string _currentThemeText = "Dark";

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
    private string _startupStatusText = "Autostart: off";

    [ObservableProperty]
    private bool _canRepairStartup;

    partial void OnTrayNotificationsEnabledChanged(bool value) =>
        TraySettingsStore.SetEnabled(value);

    partial void OnNotificationsEnabledChanged(bool value) =>
        NotificationSettingsStore.SetEnabled(value);

    partial void OnHideBackgroundWindowsChanged(bool value) =>
        BackgroundWindowSettingsStore.SetEnabled(value);

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

    public void Dispose() => _theme.Changed -= OnThemeChanged;

    [RelayCommand]
    private void UseDarkTheme() => _theme.Apply(UiTheme.Dark);

    [RelayCommand]
    private void UseLightTheme() => _theme.Apply(UiTheme.Light);

    [RelayCommand]
    private void UseDarkMidnightTheme() => _theme.Apply(UiTheme.DarkMidnight);

    [RelayCommand]
    private void UseLightWarmTheme() => _theme.Apply(UiTheme.LightWarm);

    private void OnThemeChanged(object? sender, EventArgs e) =>
        CurrentThemeText = ThemeLabel(_theme.Current);

    private static string ThemeLabel(UiTheme theme) => theme switch
    {
        UiTheme.Light => "Light",
        UiTheme.DarkMidnight => "Dark Midnight",
        UiTheme.LightWarm => "Light Warm",
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
