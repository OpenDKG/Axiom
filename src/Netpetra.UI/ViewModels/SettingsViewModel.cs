// SPDX-License-Identifier: GPL-3.0-or-later
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Netpetra.Contracts;
using Netpetra.Contracts.Ipc;
using Netpetra.UI.Services;

namespace Netpetra.UI.ViewModels;

public sealed partial class SettingsViewModel : PageViewModel, IDisposable
{
    public SettingsViewModel(ConnectionMonitor monitor)
        : base("Settings", "Appearance and build information", "\uE713")
    {
        ArgumentNullException.ThrowIfNull(monitor);

        CollectorText = monitor.SourceName;
        PollText = $"{monitor.PollInterval.TotalSeconds:0} s · read-only";

        ThemeManager.Changed += OnThemeChanged;
        TraySettingsStore.Changed += OnTraySettingsChanged;
        UpdateThemeText();

        var startup = _startupSettings.Load();
        _updatingStartup = true;
        IsAutostartSupported = !DistributionContext.IsStorePackage;
        StartWithWindows = IsAutostartSupported &&
                           _autostart.Read().State is AutostartState.Enabled or AutostartState.Stale;
        StartMinimized = startup.StartMinimized;
        _updatingStartup = false;
        UpdateStartupStatus();
    }

    public bool IsAutostartSupported { get; }

    public string MilestoneText => ProductMilestone.Current;

    public string ProtocolText => ConnectionSourceRegistry.IsServiceMode
        ? $"IPC contract v{IpcProtocol.CurrentVersion} (service connected)"
        : $"IPC contract v{IpcProtocol.CurrentVersion} (not connected)";

    public string DataModeText => ConnectionSourceRegistry.IsLive
        ? "LIVE — local socket inventory, no telemetry"
        : "DEMO — generated rows, no OS telemetry";

    public string CollectorText { get; }

    public string PollText { get; }

    public string StorageText => DistributionContext.IsStorePackage
        ? "Package-local application data managed by Windows for this Store package"
        : @"%LOCALAPPDATA%\Netpetra\netpetra.db (service mode; ProgramData for a service account)";

    public string OsText => Environment.OSVersion.VersionString;

    public string ProcessText =>
        $"{System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture} · 64-bit process: " +
        $"{(Environment.Is64BitProcess ? "yes" : "no")}";

    [ObservableProperty]
    private string _currentThemeText = "Dark";

    [ObservableProperty]
    private bool _trayNotificationsEnabled = TraySettingsStore.Enabled;

    partial void OnTrayNotificationsEnabledChanged(bool value) => TraySettingsStore.SetEnabled(value);


    private readonly StartupSettingsStore _startupSettings = new();

    private readonly AutostartRegistration _autostart = new();

    private bool _updatingStartup;

    [ObservableProperty]
    private bool _startWithWindows;

    [ObservableProperty]
    private bool _startMinimized;

    [ObservableProperty]
    private string _startupStatusText = "Autostart: off";

    [ObservableProperty]
    private bool _canRepairStartup;

    partial void OnStartWithWindowsChanged(bool value)
    {
        if (_updatingStartup || !IsAutostartSupported)
        {
            return;
        }

        var success = value ? _autostart.Enable() : _autostart.Disable();
        if (!success)
        {
            _updatingStartup = true;
            StartWithWindows = _autostart.Read().State is AutostartState.Enabled or AutostartState.Stale;
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

        var success = _autostart.Enable();
        _updatingStartup = true;
        StartWithWindows = success;
        _updatingStartup = false;
        SaveStartupPreferences();
        UpdateStartupStatus();
    }

    private void SaveStartupPreferences() =>
        _startupSettings.Save(new StartupSettings(
            StartWithWindows,
            StartMinimized,
            _autostart.ExecutablePath,
            DateTimeOffset.UtcNow));

    private void UpdateStartupStatus()
    {
        if (!IsAutostartSupported)
        {
            CanRepairStartup = false;
            StartupStatusText = "Autostart: managed by Windows for Store packages";
            return;
        }

        var status = _autostart.Read();
        CanRepairStartup = status.State == AutostartState.Stale;
        StartupStatusText = status.State switch
        {
            AutostartState.Enabled => "Autostart: active",
            AutostartState.Stale => "Autostart: path is stale; repair",
            AutostartState.Unavailable => "Autostart: unavailable (permission/policy)",
            _ => "Autostart: off",
        };
    }

    [RelayCommand]
    private static void UseDarkTheme() => ThemeManager.Apply(AppTheme.Dark);

    [RelayCommand]
    private static void UseLightTheme() => ThemeManager.Apply(AppTheme.Light);

    [RelayCommand]
    private static void UseDarkMidnightTheme() => ThemeManager.Apply(AppTheme.DarkMidnight);

    [RelayCommand]
    private static void UseLightWarmTheme() => ThemeManager.Apply(AppTheme.LightWarm);

    public void Dispose()
    {
        ThemeManager.Changed -= OnThemeChanged;
        TraySettingsStore.Changed -= OnTraySettingsChanged;
    }

    private void OnTraySettingsChanged(object? sender, EventArgs e) =>
        TrayNotificationsEnabled = TraySettingsStore.Enabled;

    private void OnThemeChanged(object? sender, EventArgs e) => UpdateThemeText();

    private void UpdateThemeText() =>
        CurrentThemeText = ThemeManager.Current.ToString();
}
