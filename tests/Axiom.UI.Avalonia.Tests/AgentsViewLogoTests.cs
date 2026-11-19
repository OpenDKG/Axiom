// SPDX-License-Identifier: GPL-3.0-or-later
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Axiom.UI.Avalonia.Views;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class AgentsViewLogoTests
{
    [Fact]
    public void Logo_marks_fit_the_cards_and_gain_a_shadow_only_in_light_themes()
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
                    Assert.InRange(logo.DesiredSize.Width, 140, 236);
                    Assert.InRange(logo.DesiredSize.Height, 35, 41);
                }

                foreach (var theme in new[] { ThemeVariant.Light, AxiomThemeVariants.LightWarm, AxiomThemeVariants.GlassLight })
                {
                    window.RequestedThemeVariant = theme;
                    Dispatcher.UIThread.RunJobs();
                    Assert.All(logos, logo => Assert.IsAssignableFrom<IDropShadowEffect>(logo.Effect));
                }

                foreach (var theme in new[] { ThemeVariant.Dark, AxiomThemeVariants.DarkMidnight, AxiomThemeVariants.GlassDark })
                {
                    window.RequestedThemeVariant = theme;
                    Dispatcher.UIThread.RunJobs();
                    Assert.All(logos, logo => Assert.Null(logo.Effect));
                }

                window.Width = 640;
                window.UpdateLayout();
                Dispatcher.UIThread.RunJobs();
                var blackboxCard = view.FindControl<Border>("BlackboxModuleCard");
                Assert.NotNull(blackboxCard);
                var first = logos[1].TranslatePoint(new Point(0, 0), blackboxCard);
                var second = logos[2].TranslatePoint(new Point(0, 0), blackboxCard);
                Assert.NotNull(first);
                Assert.NotNull(second);
                Assert.True(second.Value.Y > first.Value.Y);
                Assert.True(first.Value.X + logos[1].Bounds.Width <= blackboxCard.Bounds.Width);
                Assert.True(second.Value.X + logos[2].Bounds.Width <= blackboxCard.Bounds.Width);
            }
            finally
            {
                window.Close();
            }
        });
    }
}
