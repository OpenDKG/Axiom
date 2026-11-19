// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Contracts.Ai;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class AiAnalystSafetyTests
{
    [Fact]
    public void OpenCode_request_uses_independent_server_and_deny_all_tool_configuration()
    {
        var workingDirectory = Path.GetTempPath();
        var start = OpenCodeAnalystLaunch.CreateRequest("opencode", workingDirectory, "example/model");

        Assert.Equal(["run", "--standalone", "--format", "json", "--agent", "axiom-analyst", "--model", "example/model"],
            start.ArgumentList);
        Assert.False(start.UseShellExecute);
        Assert.True(start.RedirectStandardInput);
        Assert.Equal(Path.Combine(workingDirectory, "config"), start.Environment["XDG_CONFIG_HOME"]);
        Assert.Equal(":memory:", start.Environment["OPENCODE_DB"]);
        Assert.Equal("true", start.Environment["OPENCODE_DISABLE_PROJECT_CONFIG"]);
        Assert.False(start.Environment.ContainsKey("OPENCODE_CONFIG_DIR"));
        Assert.False(start.Environment.ContainsKey("OPENCODE_CONFIG"));
        Assert.False(start.Environment.ContainsKey("OPENCODE_CLI_CONFIG_CONTENT"));

        using var config = JsonDocument.Parse(start.Environment["OPENCODE_CONFIG_CONTENT"]!);
        var agent = config.RootElement.GetProperty("agents").GetProperty("axiom-analyst");
        var permission = Assert.Single(agent.GetProperty("permissions").EnumerateArray());
        Assert.Equal("*", permission.GetProperty("action").GetString());
        Assert.Equal("*", permission.GetProperty("resource").GetString());
        Assert.Equal("deny", permission.GetProperty("effect").GetString());
        var policies = config.RootElement.GetProperty("policies").EnumerateArray().ToArray();
        Assert.Equal(["tool.use", "mcp.use", "plugin.use", "skill.use"],
            policies.Select(policy => policy.GetProperty("action").GetString()));
        Assert.All(policies, policy =>
        {
            Assert.Equal("*", policy.GetProperty("resource").GetString());
            Assert.Equal("deny", policy.GetProperty("effect").GetString());
        });
    }

    [Theory]
    [InlineData("SUSPICIOUS", "high", null, "High-priority finding")]
    [InlineData("SUPPORTED_ALERT", "critical", null, "High-priority finding")]
    [InlineData("SUSPICIOUS", "medium", null, "Flagged for review")]
    [InlineData("LOW_OBSERVED_RISK", "low", null, "Low observed risk")]
    [InlineData("LOW_OBSERVED_RISK", "critical", null, "Inconclusive")]
    [InlineData("INSUFFICIENT_DATA", "low", null, "Inconclusive")]
    [InlineData("SAFE", "low", null, "Inconclusive")]
    [InlineData("LOW_OBSERVED_RISK", "low", "Provider error", "Analysis failed")]
    public void Badge_classifies_existing_findings_without_changing_the_saved_contract(
        string status, string severity, string? error, string label)
    {
        var finding = new AiFinding { Status = status, Severity = severity, Error = error };
        Assert.Equal(label, finding.Assessment.Label);
        Assert.DoesNotContain("\"Assessment\"", JsonSerializer.Serialize(finding), StringComparison.Ordinal);
    }
}
