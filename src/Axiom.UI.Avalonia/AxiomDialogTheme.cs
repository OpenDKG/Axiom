// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Resolves active Axiom palette brushes for imperative dialogs and toast notifications so
/// every popup adapts cleanly across Dark, Light, Midnight, Warm, and Glass themes.
/// </summary>
internal static class AxiomDialogTheme
{
    public static IBrush WindowBackground => ResolveOpaqueBrush("Axiom.PopupSurface", "#12151C");

    public static IBrush Surface => ResolveOpaqueBrush("Axiom.Surface", "#161B22");

    public static IBrush SurfaceAlt => ResolveOpaqueBrush("Axiom.SurfaceAlt", "#1A2430");

    public static IBrush Border => ResolveBrush("Axiom.Border", "#2E3A47");

    public static IBrush TextPrimary => ResolveBrush("Axiom.TextPrimary", "#F3F5F8");

    public static IBrush TextMuted => ResolveBrush("Axiom.TextMuted", "#9EA7B8");

    public static IBrush Accent => ResolveBrush("Axiom.Accent", "#1F6FEB");

    public static IBrush AccentContrast => ResolveBrush("Axiom.AccentContrast", "#FFFFFF");

    public static IBrush Critical => ResolveBrush("Axiom.Critical", "#F87171");

    public static IBrush ResolveBrush(string key, string fallbackHex)
    {
        if (TryFindBrush(key, out var brush))
        {
            return brush;
        }

        return new SolidColorBrush(Color.Parse(fallbackHex));
    }

    private static IBrush ResolveOpaqueBrush(string key, string fallbackHex)
    {
        if (TryFindBrush(key, out var brush) && brush is ISolidColorBrush solid)
        {
            var color = solid.Color;
            return color.A == byte.MaxValue
                ? solid
                : new SolidColorBrush(Color.FromRgb(color.R, color.G, color.B));
        }

        return new SolidColorBrush(Color.Parse(fallbackHex));
    }

    private static bool TryFindBrush(string key, out IBrush brush)
    {
        var app = Application.Current;
        if (app is not null &&
            app.TryFindResource(key, app.ActualThemeVariant, out var value) &&
            value is IBrush resolved)
        {
            brush = resolved;
            return true;
        }

        brush = null!;
        return false;
    }
}
