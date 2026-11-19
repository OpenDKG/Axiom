// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Avalonia;
using Avalonia.Platform;
using Avalonia.Styling;
using Axiom.Presentation;
using Axiom.UI.Avalonia;

namespace Axiom.Desktop.Avalonia.MacOS;

/// <summary>
/// Applies the portable theme choice. Until the user picks a palette, Axiom follows the macOS
/// appearance (System Settings &gt; Appearance) and keeps following it when it changes.
/// </summary>
public sealed class MacThemeService : IThemeService
{
    private bool _followSystem;

    public MacThemeService()
    {
        _followSystem = !ThemeSettingsStore.HasSavedTheme;
        Current = _followSystem ? SystemTheme() : ThemeSettingsStore.Load();
    }

    public UiTheme Current { get; private set; }

    public event EventHandler? Changed;

    public void Apply(UiTheme theme)
    {
        if (theme == Current && _followSystem)
        {
            // The shell echoes the initial selection back; that is not an explicit user choice.
            ApplyVariant(theme);
            return;
        }

        _followSystem = false;
        Current = theme;
        ThemeSettingsStore.Save(theme);
        ApplyVariant(theme);
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Subscribes to macOS appearance changes while no explicit palette is saved.</summary>
    public void AttachToPlatform(Application application)
    {
        ArgumentNullException.ThrowIfNull(application);
        var settings = application.PlatformSettings;
        if (settings is null)
        {
            return;
        }

        if (_followSystem)
        {
            Current = FromPlatform(settings.GetColorValues().ThemeVariant);
        }

        settings.ColorValuesChanged += (_, values) =>
        {
            if (!_followSystem)
            {
                return;
            }

            var theme = FromPlatform(values.ThemeVariant);
            if (theme == Current)
            {
                return;
            }

            Current = theme;
            ApplyVariant(theme);
            Changed?.Invoke(this, EventArgs.Empty);
        };
    }

    public static ThemeVariant VariantFor(UiTheme theme) => theme switch
    {
        UiTheme.Light => ThemeVariant.Light,
        UiTheme.DarkMidnight => AxiomThemeVariants.DarkMidnight,
        UiTheme.LightWarm => AxiomThemeVariants.LightWarm,
        _ => ThemeVariant.Dark,
    };

    internal static UiTheme FromPlatform(PlatformThemeVariant variant) =>
        variant == PlatformThemeVariant.Light ? UiTheme.Light : UiTheme.Dark;

    /// <summary><c>defaults read -g AppleInterfaceStyle</c> prints <c>Dark</c> in dark mode and fails in light mode.</summary>
    internal static UiTheme FromAppleInterfaceStyle(int exitCode, string output) =>
        exitCode == 0 && output.Trim().Equals("Dark", StringComparison.OrdinalIgnoreCase)
            ? UiTheme.Dark
            : UiTheme.Light;

    private static UiTheme SystemTheme()
    {
        if (!OperatingSystem.IsMacOS())
        {
            return UiTheme.Dark;
        }

        try
        {
            var startInfo = new ProcessStartInfo("/usr/bin/defaults")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            startInfo.ArgumentList.Add("read");
            startInfo.ArgumentList.Add("-g");
            startInfo.ArgumentList.Add("AppleInterfaceStyle");
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return UiTheme.Dark;
            }

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(3000);
            return FromAppleInterfaceStyle(process.HasExited ? process.ExitCode : 1, output);
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return UiTheme.Dark;
        }
    }

    private static void ApplyVariant(UiTheme theme)
    {
        if (Application.Current is { } application)
        {
            application.RequestedThemeVariant = VariantFor(theme);
        }
    }
}
