// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using System.Xml.Linq;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class ThemeContrastTests
{
    private static readonly string[] TextRoles =
    [
        "Brush.TextPrimary",
        "Brush.TextSecondary",
        "Brush.TextMuted",
    ];

    private static readonly string[] Surfaces =
    [
        "Brush.WindowBackground",
        "Brush.Surface",
        "Brush.SurfaceAlt",
        "Brush.NavHover",
        "Brush.NavSelected",
        "Brush.AccentSoft",
    ];

    [Theory]
    [InlineData("Dark.xaml")]
    [InlineData("DarkMidnight.xaml")]
    [InlineData("Light.xaml")]
    [InlineData("LightWarm.xaml")]
    public void Normal_text_roles_meet_wcag_aa_on_every_surface(string theme)
    {
        var palette = LoadPalette(theme);
        foreach (var role in TextRoles)
        {
            foreach (var surface in Surfaces)
            {
                Assert.True(
                    Contrast(palette[role], palette[surface]) >= 4.5,
                    $"{theme}: {role} on {surface} is {Contrast(palette[role], palette[surface]):F2}:1");
            }
        }
    }

    [Theory]
    [InlineData("Dark.xaml")]
    [InlineData("DarkMidnight.xaml")]
    public void Dark_theme_structural_border_meets_three_to_one(string theme)
    {
        var palette = LoadPalette(theme);
        foreach (var surface in new[] { "Brush.Surface", "Brush.SurfaceAlt", "Brush.NavSelected" })
        {
            Assert.True(
                Contrast(palette["Brush.BorderStrong"], palette[surface]) >= 3.0,
                $"{theme}: BorderStrong on {surface} is {Contrast(palette["Brush.BorderStrong"], palette[surface]):F2}:1");
        }
    }

    [Theory]
    [InlineData("Dark.xaml")]
    [InlineData("DarkMidnight.xaml")]
    [InlineData("Light.xaml")]
    [InlineData("LightWarm.xaml")]
    public void Demo_badge_text_meets_wcag_aa(string theme)
    {
        var palette = LoadPalette(theme);
        Assert.True(
            Contrast(palette["Brush.DemoBadgeText"], palette["Brush.DemoBadgeBackground"]) >= 4.5,
            $"{theme}: DemoBadgeText is {Contrast(palette["Brush.DemoBadgeText"], palette["Brush.DemoBadgeBackground"]):F2}:1");
    }

    private static Dictionary<string, string> LoadPalette(string theme)
    {
        var file = Path.Combine(RepositoryRoot(), "src", "Axiom.UI", "Themes", theme);
        var document = XDocument.Load(file);
        XNamespace x = "http://schemas.microsoft.com/winfx/2006/xaml";
        return document.Descendants()
            .Where(element => element.Name.LocalName == "SolidColorBrush")
            .ToDictionary(
                element => element.Attribute(x + "Key")!.Value,
                element => element.Attribute("Color")!.Value);
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "Axiom.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }

    private static double Contrast(string foreground, string background)
    {
        var first = RelativeLuminance(foreground);
        var second = RelativeLuminance(background);
        var lighter = Math.Max(first, second);
        var darker = Math.Min(first, second);
        return (lighter + 0.05) / (darker + 0.05);
    }

    private static double RelativeLuminance(string color)
    {
        var value = color.TrimStart('#');
        var red = Channel(value[0..2]);
        var green = Channel(value[2..4]);
        var blue = Channel(value[4..6]);
        return (0.2126 * red) + (0.7152 * green) + (0.0722 * blue);
    }

    private static double Channel(string value)
    {
        var channel = int.Parse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture) / 255.0;
        return channel <= 0.04045
            ? channel / 12.92
            : Math.Pow((channel + 0.055) / 1.055, 2.4);
    }
}
