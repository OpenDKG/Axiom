// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Avalonia;
using Avalonia.Platform;
using Avalonia.Styling;
using Axiom.Presentation;
using Axiom.UI.Avalonia;

namespace Axiom.Desktop.Avalonia.Linux;

/// <summary>
/// Applies the portable theme choice. Until the user picks a palette, Axiom follows the desktop
/// colour scheme from <c>org.freedesktop.portal.Settings</c> (<c>org.freedesktop.appearance
/// color-scheme</c>: 1 = prefer dark, 2 = prefer light, 0 = no preference) and keeps following it:
/// Avalonia's freedesktop backend subscribes to the portal's <c>SettingChanged</c> signal and
/// raises <see cref="IPlatformSettings.ColorValuesChanged"/>.
/// </summary>
public sealed class LinuxThemeService : IThemeService
{
    private bool _followSystem;

    public LinuxThemeService()
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

    /// <summary>Subscribes to colour-scheme changes while no explicit palette is saved.</summary>
    public void AttachToPlatform(Application application)
    {
        ArgumentNullException.ThrowIfNull(application);
        var settings = application.PlatformSettings;
        if (settings is null)
        {
            return;
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
        UiTheme.GlassDark => AxiomThemeVariants.GlassDark,
        UiTheme.GlassLight => AxiomThemeVariants.GlassLight,
        _ => ThemeVariant.Dark,
    };

    internal static UiTheme FromPlatform(PlatformThemeVariant variant) =>
        variant == PlatformThemeVariant.Light ? UiTheme.Light : UiTheme.Dark;

    /// <summary>
    /// Parses <c>dbus-send --print-reply</c> output of the portal <c>Read</c> call, e.g.
    /// <c>variant variant uint32 1</c>. 2 = light; 1, 0 and anything unreadable = dark (Axiom's default).
    /// </summary>
    internal static UiTheme FromPortalColorScheme(int exitCode, string output)
    {
        if (exitCode != 0)
        {
            return UiTheme.Dark;
        }

        var index = output.LastIndexOf("uint32", StringComparison.Ordinal);
        if (index < 0)
        {
            return UiTheme.Dark;
        }

        var value = output[(index + "uint32".Length)..].Trim();
        return value.StartsWith('2') ? UiTheme.Light : UiTheme.Dark;
    }

    private static UiTheme SystemTheme()
    {
        if (!OperatingSystem.IsLinux())
        {
            return UiTheme.Dark;
        }

        try
        {
            var startInfo = new ProcessStartInfo("/usr/bin/dbus-send")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            foreach (var argument in new[]
                     {
                         "--session", "--print-reply", "--dest=org.freedesktop.portal.Desktop",
                         "/org/freedesktop/portal/desktop", "org.freedesktop.portal.Settings.Read",
                         "string:org.freedesktop.appearance", "string:color-scheme",
                     })
            {
                startInfo.ArgumentList.Add(argument);
            }

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return UiTheme.Dark;
            }

            var output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(3000))
            {
                process.Kill();
                return UiTheme.Dark;
            }

            return FromPortalColorScheme(process.ExitCode, output);
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
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
