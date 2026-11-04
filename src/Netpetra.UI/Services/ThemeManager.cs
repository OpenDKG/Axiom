// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Windows;

namespace Netpetra.UI.Services;

public enum AppTheme
{
    Dark,
    Light,
}

/// <summary>
/// Swaps the palette ResourceDictionary at runtime. Control styles stay in place and reference the
/// palette with DynamicResource, so no view code needs to know about the current theme.
/// </summary>
public static class ThemeManager
{
    private static readonly string[] PaletteFiles = ["Dark.xaml", "Light.xaml"];

    public static AppTheme Current { get; private set; } = AppTheme.Dark;

    public static event EventHandler? Changed;

    public static void Toggle() =>
        Apply(Current == AppTheme.Dark ? AppTheme.Light : AppTheme.Dark);

    public static void Apply(AppTheme theme)
    {
        var application = Application.Current
            ?? throw new InvalidOperationException("ThemeManager requires a running WPF application.");

        var merged = application.Resources.MergedDictionaries;
        var palette = new ResourceDictionary
        {
            // Absolute pack URI: the Desktop host is the entry assembly, but the palette lives
            // in Netpetra.UI.
            Source = new Uri(
                $"pack://application:,,,/Netpetra.UI;component/Themes/{theme}.xaml",
                UriKind.Absolute),
        };

        var index = FindPaletteIndex(merged);
        if (index >= 0)
        {
            merged[index] = palette;
        }
        else
        {
            merged.Insert(0, palette);
        }

        Current = theme;
        ThemeSettingsStore.Save(theme);
        Changed?.Invoke(null, EventArgs.Empty);
    }

    private static int FindPaletteIndex(Collection<ResourceDictionary> merged)
    {
        for (var i = merged.Count - 1; i >= 0; i--)
        {
            var source = merged[i].Source?.OriginalString;
            if (source is not null &&
                PaletteFiles.Any(file => source.EndsWith(file, StringComparison.OrdinalIgnoreCase)))
            {
                return i;
            }
        }

        return -1;
    }
}
