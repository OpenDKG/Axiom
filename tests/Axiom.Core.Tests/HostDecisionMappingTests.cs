// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Core.Enforcement;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class HostDecisionMappingTests
{
    private static readonly DateTimeOffset Observed =
        new(2026, 11, 11, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("read_file", AgentActionKind.ReadFile)]
    [InlineData("view", AgentActionKind.ReadFile)]
    [InlineData("write", AgentActionKind.WriteFile)]
    [InlineData("apply_patch", AgentActionKind.WriteFile)]
    [InlineData("delete", AgentActionKind.DeleteFile)]
    [InlineData("bash", AgentActionKind.ExecuteProcess)]
    [InlineData("powershell", AgentActionKind.ExecuteProcess)]
    [InlineData("webfetch", AgentActionKind.HttpRequest)]
    [InlineData("connect", AgentActionKind.NetworkConnect)]
    [InlineData("todo_write", AgentActionKind.ToolCall)]
    [InlineData("", AgentActionKind.ToolCall)]
    [InlineData(null, AgentActionKind.ToolCall)]
    public void Tool_names_map_to_action_kinds(string? tool, AgentActionKind expected)
    {
        Assert.Equal(expected, HostDecisionMapping.MapToolKind(tool));
    }

    [Fact]
    public void Request_keeps_identity_target_and_host_time()
    {
        var request = HostDecisionMapping.MapRequest(
            "req-1", "claude", "session-1", "read_file", @"C:\work\a.cs", null, Observed);

        Assert.Equal("req-1", request.RequestId);
        Assert.Equal("claude", request.AgentId);
        Assert.Equal("session-1", request.SessionId);
        Assert.Equal(AgentActionKind.ReadFile, request.Kind);
        Assert.Equal(@"C:\work\a.cs", request.Target);
        Assert.Equal(Observed, request.UtcTime);
    }

    [Fact]
    public void Block_uses_the_claude_style_payload_for_supported_hosts()
    {
        var verdict = Verdict(EnforcementDecision.Block);

        var json = HostDecisionMapping.ToHostResponse(HostHarness.ClaudeCode, verdict, "blocked by test");
        Assert.NotNull(json);

        using var document = JsonDocument.Parse(json);
        var hook = document.RootElement.GetProperty("hookSpecificOutput");
        Assert.Equal("PreToolUse", hook.GetProperty("hookEventName").GetString());
        Assert.Equal("deny", hook.GetProperty("permissionDecision").GetString());
        Assert.Equal("blocked by test", hook.GetProperty("permissionDecisionReason").GetString());
    }

    [Fact]
    public void Block_uses_the_codex_payload_for_codex()
    {
        var verdict = Verdict(EnforcementDecision.Block);

        var json = HostDecisionMapping.ToHostResponse(HostHarness.Codex, verdict);
        Assert.NotNull(json);

        using var document = JsonDocument.Parse(json);
        Assert.Equal("block", document.RootElement.GetProperty("decision").GetString());
        Assert.Equal(HostDecisionMapping.DefaultBlockMessage, document.RootElement.GetProperty("reason").GetString());
        Assert.False(document.RootElement.TryGetProperty("hookSpecificOutput", out _));
    }

    [Theory]
    [InlineData(EnforcementDecision.Allow)]
    [InlineData(EnforcementDecision.Ask)]
    [InlineData(EnforcementDecision.Audit)]
    [InlineData(EnforcementDecision.Unavailable)]
    public void Non_block_verdicts_never_produce_a_deny_payload(EnforcementDecision decision)
    {
        Assert.Null(HostDecisionMapping.ToHostResponse(HostHarness.ClaudeCode, Verdict(decision)));
        Assert.Null(HostDecisionMapping.ToHostResponse(HostHarness.Codex, Verdict(decision)));
    }

    [Fact]
    public void Block_at_observation_strength_is_still_a_request_not_a_claim()
    {
        var verdict = Verdict(EnforcementDecision.Block) with
        {
            AvailableStrength = EnforcementStrength.Observation,
        };

        Assert.False(verdict.CanEnforce);
        Assert.NotNull(HostDecisionMapping.ToHostResponse(HostHarness.ClaudeCode, verdict));
    }

    private static AgentActionVerdict Verdict(EnforcementDecision decision) => new()
    {
        RequestId = "req-1",
        Decision = decision,
        RuleId = "rule-1",
        ReasonCode = EnforcementReasonCodes.RuleBlock,
        AvailableStrength = EnforcementStrength.HostHook,
    };
}
