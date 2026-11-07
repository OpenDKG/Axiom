// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Styling;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Custom Avalonia theme variants. They inherit from a built-in variant so Fluent controls keep a
/// readable base while the Axiom resource dictionaries override the palette.
/// </summary>
public static class AxiomThemeVariants
{
    public static ThemeVariant DarkMidnight { get; } =
        new("DarkMidnight", ThemeVariant.Dark);

    public static ThemeVariant LightWarm { get; } =
        new("LightWarm", ThemeVariant.Light);
}
