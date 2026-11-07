// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Styling;
using Axiom.Presentation;

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
            application.RequestedThemeVariant = theme == UiTheme.Light
                ? ThemeVariant.Light
                : ThemeVariant.Dark;
        }

        Changed?.Invoke(this, EventArgs.Empty);
    }
}
