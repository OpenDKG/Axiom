// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Styling;
using Axiom.Presentation;
using Axiom.UI.Avalonia;

namespace Axiom.Desktop.Avalonia.Windows;

/// <summary>Applies the portable theme choice to Avalonia's requested theme variant.</summary>
public sealed class WindowsThemeService : IThemeService
{
    public WindowsThemeService()
    {
        Current = ThemeSettingsStore.Load();
    }

    public UiTheme Current { get; private set; }

    public event EventHandler? Changed;

    public void Apply(UiTheme theme)
    {
        Current = theme;
        ThemeSettingsStore.Save(theme);

        if (Application.Current is { } application)
        {
            application.RequestedThemeVariant = VariantFor(theme);
        }

        Changed?.Invoke(this, EventArgs.Empty);
    }

    private static ThemeVariant VariantFor(UiTheme theme) => theme switch
    {
        UiTheme.Light => ThemeVariant.Light,
        UiTheme.DarkMidnight => AxiomThemeVariants.DarkMidnight,
        UiTheme.LightWarm => AxiomThemeVariants.LightWarm,
        UiTheme.GlassDark => AxiomThemeVariants.GlassDark,
        UiTheme.GlassLight => AxiomThemeVariants.GlassLight,
        _ => ThemeVariant.Dark,
    };
}

/// <summary>Persists and broadcasts the user's Simple / Advanced shell mode preference.</summary>
public sealed class WindowsUiModeService : IUiModeService
{
    public WindowsUiModeService()
    {
        Current = UiModeSettingsStore.Load();
    }

    public UiMode Current { get; private set; }

    public event EventHandler? Changed;

    public void Apply(UiMode mode)
    {
        if (Current == mode)
        {
            return;
        }

        Current = mode;
        UiModeSettingsStore.Save(mode);
        Changed?.Invoke(this, EventArgs.Empty);
    }
}
