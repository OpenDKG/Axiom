// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.UI.Services;
using Xunit;

namespace Netpetra.UI.Tests;

public sealed class BlackboxYamlModeTests
{
    [Fact]
    public void SetMode_changes_only_the_mode_value_and_keeps_comments()
    {
        const string yaml = """
            # user comment
            plugins:
              entries:
                blackbox:
                  mode: audit # keep this comment
                  severity: high
              enabled:
                - blackbox
            """;

        var updated = BlackboxYamlMode.SetMode(yaml, "block");

        Assert.NotNull(updated);
        Assert.Contains("# user comment", updated, StringComparison.Ordinal);
        Assert.Contains("mode: block # keep this comment", updated, StringComparison.Ordinal);
        Assert.Contains("severity: high", updated, StringComparison.Ordinal);
        Assert.Contains("  - blackbox", updated, StringComparison.Ordinal);
        Assert.Equal("block", BlackboxYamlMode.ReadMode(updated));
    }

    [Fact]
    public void SetMode_preserves_crlf_line_endings()
    {
        const string yaml = "plugins:\r\n  entries:\r\n    blackbox:\r\n      mode: audit\r\n";
        var updated = BlackboxYamlMode.SetMode(yaml, "block");

        Assert.NotNull(updated);
        Assert.Equal("plugins:\r\n  entries:\r\n    blackbox:\r\n      mode: block\r\n", updated);
    }

    [Fact]
    public void SetMode_returns_null_when_the_expected_yaml_path_is_missing()
    {
        Assert.Null(BlackboxYamlMode.SetMode("other: value\n", "block"));
    }

    [Fact]
    public void ReadMode_handles_quoted_values()
    {
        Assert.Equal("block", BlackboxYamlMode.ReadMode("""
            plugins:
              entries:
                blackbox:
                  mode: "block"
            """));
    }
}
