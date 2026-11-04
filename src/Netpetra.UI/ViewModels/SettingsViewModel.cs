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
        UpdateThemeText();
    }

    public string MilestoneText => ProductMilestone.Current;

    public string ProtocolText => ConnectionSourceRegistry.IsServiceMode
        ? $"IPC contract v{IpcProtocol.CurrentVersion} (service connected)"
        : $"IPC contract v{IpcProtocol.CurrentVersion} (not connected)";

    public string DataModeText => ConnectionSourceRegistry.IsLive
        ? "LIVE — local socket inventory, no telemetry"
        : "DEMO — generated rows, no OS telemetry";

    public string CollectorText { get; }

    public string PollText { get; }

    public string StorageText => @"%LOCALAPPDATA%\Netpetra\netpetra.db (service mode; ProgramData for a service account)";

    public string OsText => Environment.OSVersion.VersionString;

    public string ProcessText =>
        $"{System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture} · 64-bit process: " +
        $"{(Environment.Is64BitProcess ? "yes" : "no")}";

    [ObservableProperty]
    private string _currentThemeText = "Dark";

    [RelayCommand]
    private static void UseDarkTheme() => ThemeManager.Apply(AppTheme.Dark);

    [RelayCommand]
    private static void UseLightTheme() => ThemeManager.Apply(AppTheme.Light);

    public void Dispose() => ThemeManager.Changed -= OnThemeChanged;

    private void OnThemeChanged(object? sender, EventArgs e) => UpdateThemeText();

    private void UpdateThemeText() =>
        CurrentThemeText = ThemeManager.Current == AppTheme.Dark ? "Dark" : "Light";
}
