// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class HermesPluginSettingsTests
{
    private const string Yaml = """
        plugins:
          entries:
            blackbox:
              mode: block
          enabled:
            - blackbox
          disabled: []
        """;

    [Fact]
    public void The_load_deadline_is_added_under_the_plugins_block()
    {
        var updated = HermesPluginSettings.ApplyLoadTimeout(Yaml);

        Assert.StartsWith("plugins:\n  load_timeout_seconds: 120\n", updated, StringComparison.Ordinal);
        Assert.Contains("mode: block", updated, StringComparison.Ordinal);
        Assert.Contains("- blackbox", updated, StringComparison.Ordinal);
        Assert.True(HermesPluginSettings.HasLoadTimeout(updated));
    }

    [Fact]
    public void An_existing_value_is_replaced_in_place_and_a_comment_survives()
    {
        var updated = HermesPluginSettings.ApplyLoadTimeout(
            "plugins:\n  load_timeout_seconds: 10  # slow disk\n  enabled:\n    - blackbox\n");

        Assert.Contains("load_timeout_seconds: 120 # slow disk", updated, StringComparison.Ordinal);
        Assert.DoesNotContain("load_timeout_seconds: 10", updated, StringComparison.Ordinal);
    }

    [Fact]
    public void Applying_twice_changes_nothing()
    {
        var once = HermesPluginSettings.ApplyLoadTimeout(Yaml);
        var twice = HermesPluginSettings.ApplyLoadTimeout(once);

        Assert.Equal(once, twice);
    }

    [Fact]
    public void A_config_without_a_plugins_block_gets_one()
    {
        var updated = HermesPluginSettings.ApplyLoadTimeout("model: gpt\n");

        Assert.Equal("plugins:\n  load_timeout_seconds: 120\nmodel: gpt\n", updated.Replace("\r\n", "\n"));
    }

    [Theory]
    [InlineData(5, 10)]
    [InlineData(120, 120)]
    [InlineData(5000, 600)]
    public void The_deadline_is_clamped_to_the_vendor_range(int requested, int expected)
    {
        var updated = HermesPluginSettings.ApplyLoadTimeout(Yaml, requested);

        Assert.Contains($"load_timeout_seconds: {expected}", updated, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("plugins:\n  load_timeout_seconds: 10\n", false)]
    [InlineData("plugins:\n  load_timeout_seconds: 60\n", true)]
    public void HasLoadTimeout_requires_the_minimum(string? yaml, bool expected)
    {
        Assert.Equal(expected, HermesPluginSettings.HasLoadTimeout(yaml));
    }
}
