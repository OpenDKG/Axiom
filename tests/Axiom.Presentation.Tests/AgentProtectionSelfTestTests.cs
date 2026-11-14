// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class AgentProtectionSelfTestTests
{
    [Fact]
    public void Hermes_config_prefers_local_app_data_then_profile()
    {
        var local = Path.Combine("C:", "Users", "lab", "AppData", "Local");
        var profile = Path.Combine("C:", "Users", "lab");

        var candidates = HermesConfigLocation.Candidates(local, profile);

        Assert.Equal(Path.Combine(local, "hermes", "config.yaml"), candidates[0]);
        Assert.Equal(Path.Combine(profile, ".hermes", "config.yaml"), candidates[1]);
    }

    [Fact]
    public void Hermes_config_resolution_uses_the_file_the_guard_reads()
    {
        var local = Path.Combine("C:", "Users", "lab", "AppData", "Local");
        var profile = Path.Combine("C:", "Users", "lab");
        var localConfig = Path.Combine(local, "hermes", "config.yaml");
        var profileConfig = Path.Combine(profile, ".hermes", "config.yaml");

        Assert.Equal(localConfig, HermesConfigLocation.Resolve(local, profile, _ => true));
        Assert.Equal(localConfig, HermesConfigLocation.Resolve(local, profile, path => path == localConfig || path == profileConfig));
        Assert.Equal(profileConfig, HermesConfigLocation.Resolve(local, profile, path => path == profileConfig));
        Assert.Equal(localConfig, HermesConfigLocation.Resolve(local, profile, _ => false));
    }

    [Fact]
    public void ApplyMode_sets_block_and_preserves_other_settings()
    {
        const string yaml = """
            plugins:
              entries:
                blackbox:
                  mode: audit
                  report: false
            """;

        var updated = HermesConfigLocation.ApplyMode(yaml, "block");

        Assert.True(HermesConfigLocation.IsBlockMode(updated));
        Assert.Contains("report: false", updated, StringComparison.Ordinal);
        Assert.DoesNotContain("mode: audit", updated, StringComparison.Ordinal);
    }

    [Fact]
    public void ApplyMode_adds_a_mode_line_when_missing()
    {
        const string yaml = """
            plugins:
              entries:
                blackbox:
                  report: false
            """;

        var updated = HermesConfigLocation.ApplyMode(yaml, "block");

        Assert.True(HermesConfigLocation.IsBlockMode(updated));
        Assert.Contains("report: false", updated, StringComparison.Ordinal);
    }

    [Fact]
    public void Default_checks_cover_allow_and_both_protected_cases()
    {
        var checks = AgentProtectionSelfTest.DefaultChecks();

        Assert.Contains(checks, check => !check.ExpectBlock);
        Assert.Contains(checks, check => check.ExpectBlock && check.Tool == "read");
        Assert.Contains(checks, check => check.ExpectBlock && check.Tool == "write");
    }

    [Fact]
    public void Payload_is_opencode_shaped_with_filePath()
    {
        var check = AgentProtectionSelfTest.DefaultChecks().First(item => item.Tool == "write");

        var payload = AgentProtectionSelfTest.BuildPayload(check, "self-test");

        Assert.Contains("\"filePath\"", payload, StringComparison.Ordinal);
        Assert.Contains("\"tool\":\"write\"", payload, StringComparison.Ordinal);
        Assert.DoesNotContain("\"path\"", payload, StringComparison.Ordinal);
    }

    [Fact]
    public void Block_detection_and_identifier_extraction_work()
    {
        const string blocked = """{"action":"block","message":"matched fileaccess:read:user-protected"}""";

        Assert.True(AgentProtectionSelfTest.IsBlock(blocked));
        Assert.Equal("fileaccess:read:user-protected", AgentProtectionSelfTest.Identifier(blocked));

        Assert.False(AgentProtectionSelfTest.IsBlock("{}"));
        Assert.False(AgentProtectionSelfTest.IsBlock("not-json"));
        Assert.Equal(string.Empty, AgentProtectionSelfTest.Identifier("{}"));
    }

    [Fact]
    public void Summary_reports_failures()
    {
        var results = new[]
        {
            new ProtectionCheckResult("allowed read", false, false, ""),
            new ProtectionCheckResult("protected read", true, false, ""),
        };

        Assert.False(AgentProtectionSelfTest.AllPassed(results));
        Assert.Contains("protected read=FAIL", AgentProtectionSelfTest.Summary(results), StringComparison.Ordinal);
        Assert.Contains("allowed read=PASS", AgentProtectionSelfTest.Summary(results), StringComparison.Ordinal);
    }
}
