// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Enforcement;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class EnforcementPolicyEvaluatorTests
{
    private static readonly DateTimeOffset Observed =
        new(2026, 11, 11, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Identical_input_gives_an_identical_verdict()
    {
        var policy = Policy(
            Agent("claude", EnforcementMode.Monitor, Rule("allow-project", EnforcementRuleEffect.Allow, @"C:\work")));
        var request = Request("r1", "claude", AgentActionKind.ReadFile, @"C:\work\notes.md");

        var first = new EnforcementPolicyEvaluator(policy).Evaluate(request);
        var second = new EnforcementPolicyEvaluator(policy).Evaluate(request);

        Assert.Equal(first, second);
        Assert.Equal(EnforcementDecision.Allow, first.Decision);
        Assert.Equal("allow-project", first.RuleId);
        Assert.Equal(Observed, first.EvaluatedUtc);
    }

    [Fact]
    public void Protected_resource_is_blocked_when_a_real_boundary_exists()
    {
        var policy = Policy(
            Agent("claude", EnforcementMode.Monitor, Rule("allow-secrets", EnforcementRuleEffect.Allow, @"C:\secrets")),
            new ProtectedResource { ResourceId = "secret-store", Scope = @"C:\secrets" });

        var verdict = new EnforcementPolicyEvaluator(policy).Evaluate(
            Request("r2", "claude", AgentActionKind.ReadFile, @"C:\secrets\token.txt"),
            new EnforcementCapabilities { Strength = EnforcementStrength.OsBoundary });

        Assert.Equal(EnforcementDecision.Block, verdict.Decision);
        Assert.Equal("secret-store", verdict.RuleId);
        Assert.Equal(EnforcementReasonCodes.ProtectedResource, verdict.ReasonCode);
        Assert.True(verdict.CanEnforce);
    }

    [Fact]
    public void Protected_resource_without_a_boundary_is_observed_not_blocked()
    {
        var policy = Policy(
            Agent("claude", EnforcementMode.Monitor),
            new ProtectedResource { ResourceId = "secret-store", Scope = @"C:\secrets" });

        var verdict = new EnforcementPolicyEvaluator(policy).Evaluate(
            Request("r3", "claude", AgentActionKind.ReadFile, @"C:\secrets\token.txt"));

        Assert.Equal(EnforcementDecision.Audit, verdict.Decision);
        Assert.Equal(EnforcementReasonCodes.ProtectedObserved, verdict.ReasonCode);
    }

    [Fact]
    public void Protected_operation_without_a_boundary_asks_in_protect_mode()
    {
        var policy = Policy(
            Agent("claude", EnforcementMode.ProtectSelectedOperations),
            new ProtectedResource { ResourceId = "secret-store", Scope = @"C:\secrets" });

        var verdict = new EnforcementPolicyEvaluator(policy).Evaluate(
            Request("r4", "claude", AgentActionKind.ReadFile, @"C:\secrets\token.txt"));

        Assert.Equal(EnforcementDecision.Ask, verdict.Decision);
        Assert.True(verdict.RequireUserApproval);
        Assert.Equal(EnforcementReasonCodes.ProtectedUnenforceable, verdict.ReasonCode);
        Assert.False(verdict.CanEnforce);
    }

    [Fact]
    public void Unknown_agent_does_not_inherit_another_agents_allow_rule()
    {
        var policy = Policy(
            Agent("claude", EnforcementMode.Monitor, Rule("allow-project", EnforcementRuleEffect.Allow, @"C:\work")));

        var verdict = new EnforcementPolicyEvaluator(policy).Evaluate(
            Request("r5", "unlisted-agent", AgentActionKind.ReadFile, @"C:\work\notes.md"));

        Assert.Equal(EnforcementDecision.Audit, verdict.Decision);
        Assert.Equal(EnforcementReasonCodes.NoRuleMonitor, verdict.ReasonCode);
        Assert.NotEqual("allow-project", verdict.RuleId);
    }

    [Fact]
    public void Ask_rule_requires_user_approval()
    {
        var policy = Policy(
            Agent("claude", EnforcementMode.Monitor, Rule("ask-external", EnforcementRuleEffect.Ask, "example.com")));

        var verdict = new EnforcementPolicyEvaluator(policy).Evaluate(
            Request("r6", "claude", AgentActionKind.NetworkConnect, "https://api.example.com/v1"));

        Assert.Equal(EnforcementDecision.Ask, verdict.Decision);
        Assert.True(verdict.RequireUserApproval);
        Assert.Equal("ask-external", verdict.RuleId);
    }

    [Theory]
    [InlineData(EnforcementStrength.Observation, false, false)]
    [InlineData(EnforcementStrength.HostHook, true, true)]
    [InlineData(EnforcementStrength.TrustedBroker, false, true)]
    public void Block_rule_reports_whether_it_can_be_enforced(
        EnforcementStrength strength,
        bool hostSupportsDeny,
        bool canEnforce)
    {
        var policy = Policy(
            Agent("claude", EnforcementMode.Monitor, Rule("block-secrets", EnforcementRuleEffect.Block, @"C:\secrets")));

        var verdict = new EnforcementPolicyEvaluator(policy).Evaluate(
            Request("r7", "claude", AgentActionKind.ReadFile, @"C:\secrets\token.txt"),
            new EnforcementCapabilities { Strength = strength, HostSupportsDeny = hostSupportsDeny });

        Assert.Equal(EnforcementDecision.Block, verdict.Decision);
        Assert.Equal(canEnforce, verdict.CanEnforce);
    }

    [Fact]
    public void Blackbox_block_overrides_an_allow_rule()
    {
        var policy = Policy(
            Agent("claude", EnforcementMode.Monitor, Rule("allow-project", EnforcementRuleEffect.Allow, @"C:\work")));

        var verdict = new EnforcementPolicyEvaluator(policy).Evaluate(
            Request("r8", "claude", AgentActionKind.WriteFile, @"C:\work\notes.md"),
            new EnforcementCapabilities { Strength = EnforcementStrength.HostHook, HostSupportsDeny = true },
            new BlackboxGuardSignal { IsAvailable = true, IsBlock = true, SignalId = "guard-1" });

        Assert.Equal(EnforcementDecision.Block, verdict.Decision);
        Assert.Equal(EnforcementReasonCodes.GuardBlock, verdict.ReasonCode);
        Assert.Equal("guard-1", verdict.BlackboxSignalId);
        Assert.True(verdict.CanEnforce);
    }

    [Fact]
    public void Unavailable_guard_never_produces_a_verified_block()
    {
        var policy = Policy(Agent("claude", EnforcementMode.ProtectSelectedOperations));

        var verdict = new EnforcementPolicyEvaluator(policy).Evaluate(
            Request("r9", "claude", AgentActionKind.ToolCall, "shell"),
            new EnforcementCapabilities { Strength = EnforcementStrength.Observation },
            new BlackboxGuardSignal { IsAvailable = false });

        Assert.NotEqual(EnforcementDecision.Block, verdict.Decision);
        Assert.Equal(EnforcementReasonCodes.NoRuleMonitor, verdict.ReasonCode);
        Assert.Equal(EnforcementStrength.Observation, verdict.AvailableStrength);
        Assert.False(verdict.RequireUserApproval);
    }

    [Fact]
    public void Duplicate_request_id_returns_the_first_verdict()
    {
        var policy = Policy(Agent(
            "claude",
            EnforcementMode.Monitor,
            Rule("allow-project", EnforcementRuleEffect.Allow, @"C:\work"),
            Rule("block-external", EnforcementRuleEffect.Block, "example.com")));
        var evaluator = new EnforcementPolicyEvaluator(policy);

        var first = evaluator.Evaluate(Request("r10", "claude", AgentActionKind.ReadFile, @"C:\work\notes.md"));
        var second = evaluator.Evaluate(Request("r10", "claude", AgentActionKind.NetworkConnect, "example.com"));

        Assert.Equal(EnforcementDecision.Allow, first.Decision);
        Assert.Equal(first, second);
    }

    [Theory]
    [InlineData("", "claude", 10)]
    [InlineData("r11", "", 10)]
    [InlineData("r11", "claude", 9000)]
    public void Malformed_request_is_unavailable(string requestId, string agentId, int targetLength)
    {
        var policy = Policy(Agent("claude", EnforcementMode.Monitor));
        var request = Request(requestId, agentId, AgentActionKind.ReadFile, new string('a', targetLength));

        var verdict = new EnforcementPolicyEvaluator(policy).Evaluate(request);

        Assert.Equal(EnforcementDecision.Unavailable, verdict.Decision);
        Assert.Equal(EnforcementReasonCodes.InvalidRequest, verdict.ReasonCode);
    }

    [Fact]
    public void Path_scope_matches_windows_separators_and_boundaries()
    {
        var policy = Policy(
            Agent("claude", EnforcementMode.Monitor, Rule("allow-project", EnforcementRuleEffect.Allow, @"C:\work\project")));
        var evaluator = new EnforcementPolicyEvaluator(policy);

        var inside = evaluator.Evaluate(
            Request("r12", "claude", AgentActionKind.ReadFile, @"C:\work\project\src\file.cs"));
        var outside = evaluator.Evaluate(
            Request("r13", "claude", AgentActionKind.ReadFile, @"C:\work\project-other\file.cs"));

        Assert.Equal(EnforcementDecision.Allow, inside.Decision);
        Assert.Equal(EnforcementDecision.Audit, outside.Decision);
    }

    [Theory]
    [InlineData(@"C:\work\..\secrets\token.txt")]
    [InlineData(@"C:\work\.\..\secrets\.\token.txt")]
    [InlineData(@"\\?\C:\secrets\token.txt")]
    [InlineData(@"//?/C:/work/../secrets/token.txt")]
    public void Path_scope_blocks_traversal_and_extended_prefix_escape_attempts(string escapedPath)
    {
        var policy = Policy(
            Agent("claude", EnforcementMode.Monitor, Rule("allow-project", EnforcementRuleEffect.Allow, @"C:\work")),
            new ProtectedResource { ResourceId = "secret-store", Scope = @"C:\secrets" });
        var evaluator = new EnforcementPolicyEvaluator(policy);

        var verdict = evaluator.Evaluate(
            Request($"traversal-{escapedPath.Length}", "claude", AgentActionKind.ReadFile, escapedPath),
            new EnforcementCapabilities { Strength = EnforcementStrength.HostHook, HostSupportsDeny = true });

        Assert.Equal(EnforcementDecision.Block, verdict.Decision);
        Assert.Equal("secret-store", verdict.RuleId);
        Assert.Equal(EnforcementReasonCodes.ProtectedResource, verdict.ReasonCode);
        Assert.True(verdict.CanEnforce);
    }

    [Fact]
    public void Agent_identifier_is_case_insensitive()
    {
        var policy = Policy(
            Agent("Claude", EnforcementMode.Monitor, Rule("allow-project", EnforcementRuleEffect.Allow, @"C:\work")));

        var verdict = new EnforcementPolicyEvaluator(policy).Evaluate(
            Request("r14", "claude", AgentActionKind.ReadFile, @"C:\work\notes.md"));

        Assert.Equal(EnforcementDecision.Allow, verdict.Decision);
    }

    [Fact]
    public void Invalid_policy_is_rejected_at_construction()
    {
        var policy = Policy(
            Agent("claude", EnforcementMode.Monitor, Rule("same", EnforcementRuleEffect.Allow)),
            Agent("codex", EnforcementMode.Monitor, Rule("same", EnforcementRuleEffect.Block)));

        Assert.Throws<ArgumentException>(() => new EnforcementPolicyEvaluator(policy));
    }

    [Fact]
    public void Audit_entries_are_redacted_and_deduplicated()
    {
        var policy = Policy(Agent("claude", EnforcementMode.Monitor));
        var request = Request("r15", "claude", AgentActionKind.ReadFile, @"C:\Users\me\private\token.txt");
        var verdict = new EnforcementPolicyEvaluator(policy).Evaluate(request);

        var entry = EnforcementAuditLog.FromVerdict(request, verdict);
        var log = new EnforcementAuditLog();

        Assert.Equal(EnforcementAuditRedactor.Hash(@"C:\Users\me\private\token.txt"), entry.TargetHash);
        Assert.DoesNotContain("token", entry.TargetHash, StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual("claude", entry.AgentIdHash);
        Assert.True(log.TryAppend(entry));
        Assert.False(log.TryAppend(entry));
        Assert.Equal(1, log.Count);
    }

    [Fact]
    public void Audit_log_keeps_only_the_newest_entries()
    {
        var log = new EnforcementAuditLog(capacity: 2);
        var policy = Policy(Agent("claude", EnforcementMode.Monitor));

        for (var index = 0; index < 3; index++)
        {
            var request = Request($"cap-{index}", "claude", AgentActionKind.ToolCall, "shell");
            var verdict = new EnforcementPolicyEvaluator(policy).Evaluate(request);
            Assert.True(log.TryAppend(EnforcementAuditLog.FromVerdict(request, verdict)));
        }

        var snapshot = log.Snapshot();
        Assert.Equal(2, snapshot.Count);
        Assert.Equal("cap-1", snapshot[0].EventId);
        Assert.Equal("cap-2", snapshot[1].EventId);
    }

    private static EnforcementPolicy Policy(
        AgentEnforcementPolicy agent,
        params ProtectedResource[] resources) =>
        new() { Agents = [agent], ProtectedResources = [.. resources] };

    private static EnforcementPolicy Policy(AgentEnforcementPolicy first, AgentEnforcementPolicy second) =>
        new() { Agents = [first, second] };

    private static AgentEnforcementPolicy Agent(
        string agentId,
        EnforcementMode mode,
        params EnforcementRule[] rules) =>
        new() { AgentId = agentId, Mode = mode, Rules = [.. rules] };

    private static EnforcementRule Rule(
        string ruleId,
        EnforcementRuleEffect effect,
        string? scope = null) =>
        new() { RuleId = ruleId, Effect = effect, TargetScope = scope };

    private static AgentActionRequest Request(
        string requestId,
        string agentId,
        AgentActionKind kind,
        string? target = null) =>
        new()
        {
            RequestId = requestId,
            AgentId = agentId,
            Kind = kind,
            Target = target,
            UtcTime = Observed,
        };
}
