// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Styling;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Resolves active Axiom palette brushes for imperative dialogs and toast notifications so
/// every popup adapts cleanly across Dark, Light, Midnight, Warm, and Glass themes.
/// </summary>
internal static class AxiomDialogTheme
{
    public static IBrush WindowBackground =>
        ResolveWindowBackground(Application.Current, Application.Current?.ActualThemeVariant);

    public static IBrush Surface => ResolveOpaqueBrush("Axiom.Surface", "#161B22");

    public static IBrush SurfaceAlt => ResolveOpaqueBrush("Axiom.SurfaceAlt", "#1A2430");

    public static IBrush Border => ResolveBrush("Axiom.Border", "#2E3A47");

    public static IBrush TextPrimary =>
        ResolveTextPrimary(Application.Current, Application.Current?.ActualThemeVariant);

    /// <summary>
    /// Dialog window background from the given resources (the application's by default). The
    /// macOS and Linux host palettes define no Axiom.PopupSurface; falling back to a fixed dark
    /// colour there put the theme's dark text on a dark window in the Light themes, so the
    /// palette's own Axiom.Surface is used before the fixed colour.
    /// </summary>
    internal static IBrush ResolveWindowBackground(IResourceNode? resources, ThemeVariant? variant)
    {
        foreach (var key in new[] { "Axiom.PopupSurface", "Axiom.Surface" })
        {
            if (TryFindBrush(resources, variant, key, out var brush) && brush is ISolidColorBrush solid)
            {
                return Opaque(solid);
            }
        }

        return new SolidColorBrush(Color.Parse("#12151C"));
    }

    /// <summary>Dialog body text from the given resources (the application's by default).</summary>
    internal static IBrush ResolveTextPrimary(IResourceNode? resources, ThemeVariant? variant) =>
        TryFindBrush(resources, variant, "Axiom.TextPrimary", out var brush)
            ? brush
            : new SolidColorBrush(Color.Parse("#F3F5F8"));

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

    private static ISolidColorBrush Opaque(ISolidColorBrush solid) =>
        solid.Color.A == byte.MaxValue
            ? solid
            : new SolidColorBrush(Color.FromRgb(solid.Color.R, solid.Color.G, solid.Color.B));

    private static bool TryFindBrush(IResourceNode? resources, ThemeVariant? variant, string key, out IBrush brush)
    {
        if (resources is not null &&
            resources.TryGetResource(key, variant, out var value) &&
            value is IBrush resolved)
        {
            brush = resolved;
            return true;
        }

        brush = null!;
        return false;
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
