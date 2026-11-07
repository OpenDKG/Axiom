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
    private readonly StartupSettingsStore _startupSettings = new();
    private bool _updatingStartup;

    public SettingsPageViewModel(
        ConnectionMonitor monitor,
        bool serviceMode,
        IThemeService theme,
        IAutostartService autostart)
        : base("Settings", "Appearance and build information", "G")
    {
        ArgumentNullException.ThrowIfNull(monitor);
        ArgumentNullException.ThrowIfNull(theme);
        ArgumentNullException.ThrowIfNull(autostart);
        _theme = theme;
        _autostart = autostart;

        CollectorText = monitor.SourceName;
        PollText = $"{monitor.PollInterval.TotalSeconds:0} s · read-only";
        ProtocolText = serviceMode
            ? $"IPC contract v{IpcProtocol.CurrentVersion} (service connected)"
            : $"IPC contract v{IpcProtocol.CurrentVersion} (not connected)";
        DataModeText = monitor.SourceName.Contains("demo", StringComparison.OrdinalIgnoreCase)
            ? "DEMO — generated rows, no OS telemetry"
            : "LIVE — local socket inventory, no telemetry";

        _theme.Changed += OnThemeChanged;
        CurrentThemeText = _theme.Current == UiTheme.Light ? "Light" : "Dark";

        var startup = _startupSettings.Load();
        _updatingStartup = true;
        IsAutostartSupported = autostart.IsSupported;
        StartWithWindows = autostart.IsSupported && autostart.IsEnabled;
        StartMinimized = startup.StartMinimized;
        TrayNotificationsEnabled = TraySettingsStore.Enabled;
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

    [ObservableProperty]
    private string _currentThemeText = "Dark";

    [ObservableProperty]
    private bool _trayNotificationsEnabled = true;

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

    private void OnThemeChanged(object? sender, EventArgs e) =>
        CurrentThemeText = _theme.Current == UiTheme.Light ? "Light" : "Dark";

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
