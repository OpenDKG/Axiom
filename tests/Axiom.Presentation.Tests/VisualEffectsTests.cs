// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class VisualEffectsTests
{
    [Fact]
    public void Apply_raises_one_change_and_keeps_the_choice()
    {
        var service = new FixedVisualEffectsService();
        var changes = 0;
        service.Changed += (_, _) => changes++;

        service.Apply(VisualEffects.Off);
        service.Apply(VisualEffects.Off);

        Assert.Equal(VisualEffects.Off, service.Current);
        Assert.Equal(1, changes);
    }

    [Fact]
    public void Reported_backdrop_replaces_the_default_status_once()
    {
        var service = new FixedVisualEffectsService();
        var changes = 0;
        service.Changed += (_, _) => changes++;

        service.ReportBackdrop("AcrylicBlur (native backdrop active)");
        service.ReportBackdrop("AcrylicBlur (native backdrop active)");

        Assert.Equal("AcrylicBlur (native backdrop active)", service.BackdropStatus);
        Assert.Equal(1, changes);
    }

    [Theory]
    [InlineData(VisualEffects.Auto, "Auto")]
    [InlineData(VisualEffects.Full, "Full")]
    [InlineData(VisualEffects.Reduced, "Reduced")]
    [InlineData(VisualEffects.Off, "Off")]
    public void Labels_match_the_settings_buttons(VisualEffects value, string expected)
    {
        Assert.Equal(expected, VisualEffectsLabels.Label(value));
    }
}
