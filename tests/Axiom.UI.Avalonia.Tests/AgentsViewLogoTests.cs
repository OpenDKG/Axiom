// SPDX-License-Identifier: GPL-3.0-or-later
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Styling;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Axiom.UI.Avalonia.Views;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class AgentsViewLogoTests
{
    [Fact]
    public void Module_logos_fit_unframed_sections_with_theme_specific_shadows()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var view = new AgentsView();
            var window = new Window { Width = 1024, Height = 768, Content = view };
            window.Show();
            try
            {
                Dispatcher.UIThread.RunJobs();
                var logos = view.GetVisualDescendants().OfType<Image>()
                    .Where(image => image.Classes.Contains("module-logo")).ToArray();
                Assert.Equal(3, logos.Length);
                foreach (var logo in logos)
                {
                    Assert.NotNull(logo.Source);
                    // The allocated size can exceed the artwork's aspect-ratio-preserving bounds.
                    Assert.InRange(logo.DesiredSize.Width, 140, 208);
                    Assert.InRange(logo.DesiredSize.Height, 35, 41);
                    Assert.Equal(BitmapInterpolationMode.HighQuality, RenderOptions.GetBitmapInterpolationMode(logo));
                }

                var dkgSection = view.FindControl<Border>("DkgModuleCard");
                var blackboxSection = view.FindControl<Border>("BlackboxModuleCard");
                Assert.NotNull(dkgSection);
                Assert.NotNull(blackboxSection);
                Assert.Null(dkgSection.Background);
                Assert.Null(blackboxSection.Background);
                Assert.Equal(default, dkgSection.BorderThickness);
                Assert.Equal(default, blackboxSection.BorderThickness);

                foreach (var theme in new[] { ThemeVariant.Light, AxiomThemeVariants.LightWarm, AxiomThemeVariants.GlassLight })
                {
                    window.RequestedThemeVariant = theme;
                    Dispatcher.UIThread.RunJobs();
                    Assert.All(logos, logo =>
                        Assert.Equal(Color.Parse("#242831"), Assert.IsAssignableFrom<IDropShadowEffect>(logo.Effect).Color));
                }

                foreach (var theme in new[] { ThemeVariant.Dark, AxiomThemeVariants.DarkMidnight, AxiomThemeVariants.GlassDark })
                {
                    window.RequestedThemeVariant = theme;
                    Dispatcher.UIThread.RunJobs();
                    Assert.All(logos, logo =>
                        Assert.Equal(Color.Parse("#B9C4D6"), Assert.IsAssignableFrom<IDropShadowEffect>(logo.Effect).Color));
                }

                window.Width = 640;
                window.UpdateLayout();
                Dispatcher.UIThread.RunJobs();
                var first = logos[1].TranslatePoint(new Point(0, 0), blackboxSection);
                var second = logos[2].TranslatePoint(new Point(0, 0), blackboxSection);
                Assert.NotNull(first);
                Assert.NotNull(second);
                Assert.True(second.Value.Y > first.Value.Y);
                Assert.True(first.Value.X + logos[1].Bounds.Width <= blackboxSection.Bounds.Width);
                Assert.True(second.Value.X + logos[2].Bounds.Width <= blackboxSection.Bounds.Width);
            }
            finally
            {
                window.Close();
            }
        });
    }
}
