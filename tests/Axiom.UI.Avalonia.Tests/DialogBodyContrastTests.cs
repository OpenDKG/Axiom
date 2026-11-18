// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Linq;
using Avalonia.Controls;
using Avalonia.LogicalTree;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.Threading;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// The macOS "Install the Axiom background service" confirmation showed an empty dark body. The
/// macOS and Linux hosts define their own palette without Axiom.PopupSurface, so the dialog fell
/// back to a fixed dark background while the body text took the theme's text colour: dark text on
/// a dark window in the Light themes. The body must be readable in every host palette.
/// </summary>
public sealed class DialogBodyContrastTests
{
    private const string InstallMessage =
        "Axiom monitors connections, keeps history and enforces firewall and Privacy Shield rules " +
        "through a small background service (axiomd) that runs as a launchd daemon.";

    [Theory]
    [InlineData("Light", "#F2F5F8", "#FFFFFF", "#101820")]
    [InlineData("Dark", "#0F1216", "#161B22", "#E6EDF3")]
    public void Host_palette_without_popup_surface_keeps_dialog_text_readable(
        string variant,
        string window,
        string surface,
        string text)
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            // Shape of the macOS/Linux App.axaml palettes: no Axiom.PopupSurface key.
            var themeVariant = variant == "Light" ? ThemeVariant.Light : ThemeVariant.Dark;
            var palette = new ResourceDictionary
            {
                ["Axiom.Window"] = new SolidColorBrush(Color.Parse(window)),
                ["Axiom.Surface"] = new SolidColorBrush(Color.Parse(surface)),
                ["Axiom.TextPrimary"] = new SolidColorBrush(Color.Parse(text)),
            };
            var resources = new ResourceDictionary();
            resources.ThemeDictionaries[themeVariant] = palette;

            var background = AxiomDialogTheme.ResolveWindowBackground(resources, themeVariant);
            var foreground = AxiomDialogTheme.ResolveTextPrimary(resources, themeVariant);

            Assert.True(
                Contrast(background, foreground) >= 4.5,
                $"{variant}: text {Describe(foreground)} on {Describe(background)} is not readable");
        });
    }

    [Fact]
    public void Install_service_confirmation_has_a_readable_non_empty_body()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var dialog = AvaloniaUserInteraction.CreateConfirmDialog(
                "Install the Axiom background service",
                InstallMessage,
                "Install",
                destructive: false,
                () => { });
            dialog.Show();
            Dispatcher.UIThread.RunJobs();

            var body = dialog.GetLogicalDescendants().OfType<SelectableTextBlock>().Single();
            Assert.Equal(InstallMessage, body.Text);
            Assert.True(body.IsVisible);
            Assert.True(body.Bounds.Height > 0, "the body text was not laid out");
            Assert.True(
                Contrast(dialog.Background!, body.Foreground!) >= 4.5,
                $"text {Describe(body.Foreground!)} on {Describe(dialog.Background!)} is not readable");

            dialog.Close();
        });
    }

    private static string Describe(IBrush brush) =>
        brush is ISolidColorBrush solid ? solid.Color.ToString() : brush.GetType().Name;

    private static double Contrast(IBrush a, IBrush b)
    {
        var la = Luminance(Assert.IsAssignableFrom<ISolidColorBrush>(a).Color);
        var lb = Luminance(Assert.IsAssignableFrom<ISolidColorBrush>(b).Color);
        return (Math.Max(la, lb) + 0.05) / (Math.Min(la, lb) + 0.05);
    }

    private static double Luminance(Color color)
    {
        static double Channel(byte value)
        {
            var c = value / 255.0;
            return c <= 0.03928 ? c / 12.92 : Math.Pow((c + 0.055) / 1.055, 2.4);
        }

        return (0.2126 * Channel(color.R)) + (0.7152 * Channel(color.G)) + (0.0722 * Channel(color.B));
    }
}
