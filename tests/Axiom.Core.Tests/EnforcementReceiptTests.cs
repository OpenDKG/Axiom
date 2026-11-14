// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Enforcement;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class EnforcementReceiptTests
{
    private static readonly DateTimeOffset Observed =
        new(2026, 11, 14, 6, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Create_redacts_target_path_and_secrets_into_indicator_ref()
    {
        const string secretPath = @"C:\Users\alice\.ssh\id_ed25519_super_secret";

        var receipt = EnforcementReceiptV1.Create(
            eventId: "evt-1",
            requestId: "req-1",
            policyRevision: "abc123",
            hostAdapter: "opencode",
            hostVersion: "2.0.1",
            actionKind: AgentActionKind.ReadFile,
            decisionSource: "local_policy",
            rawTargetOrIndicator: secretPath,
            requestedDecision: EnforcementDecision.Block,
            boundary: EnforcementBoundaryKind.HostHook,
            result: EnforcementReceiptResult.HostDenySent,
            observedSideEffect: EnforcementObservedSideEffect.Unknown,
            verifiedBy: null,
            timestampUtc: Observed);

        Assert.Equal(EnforcementReceiptV1.SchemaVersion, receipt.Schema);
        Assert.Equal("HOST_DENY_SENT", receipt.ResultToken);
        Assert.DoesNotContain("alice", receipt.IndicatorRef, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("id_ed25519", receipt.IndicatorRef, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(EnforcementAuditRedactor.Hash(secretPath), receipt.IndicatorRef);
    }

    [Theory]
    [InlineData(EnforcementReceiptResult.HostDenyVerified, EnforcementObservedSideEffect.Unknown, "canary")]
    [InlineData(EnforcementReceiptResult.HostDenyVerified, EnforcementObservedSideEffect.Present, "canary")]
    [InlineData(EnforcementReceiptResult.HostDenyVerified, EnforcementObservedSideEffect.Absent, null)]
    [InlineData(EnforcementReceiptResult.OsDenyVerified, EnforcementObservedSideEffect.Unknown, "wfp")]
    [InlineData(EnforcementReceiptResult.OsDenyVerified, EnforcementObservedSideEffect.Absent, "   ")]
    public void Verified_results_downgrade_to_unverified_without_absent_side_effect_and_verifier(
        EnforcementReceiptResult requested,
        EnforcementObservedSideEffect sideEffect,
        string? verifiedBy)
    {
        var receipt = EnforcementReceiptV1.Create(
            eventId: "evt-downgrade",
            requestId: "req-downgrade",
            policyRevision: "rev-1",
            hostAdapter: "codex",
            hostVersion: "1.0",
            actionKind: AgentActionKind.ExecuteProcess,
            decisionSource: "local_policy",
            rawTargetOrIndicator: @"C:\lab\cmd.exe",
            requestedDecision: EnforcementDecision.Block,
            boundary: EnforcementBoundaryKind.HostHook,
            result: requested,
            observedSideEffect: sideEffect,
            verifiedBy: verifiedBy,
            timestampUtc: Observed);

        Assert.Equal(EnforcementReceiptResult.Unverified, receipt.Result);
        Assert.Equal("UNVERIFIED", receipt.ResultToken);
        Assert.Null(receipt.VerifiedBy);
    }

    [Fact]
    public void Journal_chains_hashes_suppresses_duplicates_and_bounds_capacity()
    {
        var journal = new EnforcementReceiptJournal(capacity: 2);

        var r1 = MakeReceipt("evt-1", EnforcementReceiptResult.AuditOnly);
        var r2 = MakeReceipt("evt-2", EnforcementReceiptResult.HostDenySent);
        var r3 = EnforcementReceiptV1.Create(
            "evt-3", "req-3", "rev-1", "claude", "1.0", AgentActionKind.WriteFile,
            "local_policy", @"C:\lab\canary.txt", EnforcementDecision.Block,
            EnforcementBoundaryKind.HostHook, EnforcementReceiptResult.HostDenyVerified,
            EnforcementObservedSideEffect.Absent, "disposable-canary", Observed);

        Assert.True(journal.TryAppend(r1));
        Assert.False(journal.TryAppend(r1));
        Assert.True(journal.TryAppend(r2));
        Assert.True(journal.TryAppend(r3));

        Assert.Equal(2, journal.Count);
        Assert.True(journal.VerifyChain());

        var summary = journal.Summarize();
        Assert.Equal(2, summary.Total);
        Assert.Equal(1, summary.HostDenySent);
        Assert.Equal(1, summary.HostDenyVerified);
        Assert.Equal("HOST_DENY_VERIFIED", summary.LatestResultToken);
        Assert.True(summary.ChainValid);
    }

    [Fact]
    public void Community_only_guard_signal_stays_advisory_unless_explicit_local_rule_blocks()
    {
        var policy = new EnforcementPolicy
        {
            Version = "1",
            Agents =
            [
                new AgentEnforcementPolicy
                {
                    AgentId = "opencode",
                    Mode = EnforcementMode.Monitor,
                    Rules =
                    [
                        new EnforcementRule
                        {
                            RuleId = "block-explicit-local",
                            Effect = EnforcementRuleEffect.Block,
                            Kind = AgentActionKind.NetworkConnect,
                            TargetScope = "evil-local.example",
                        },
                    ],
                },
            ],
        };
        var evaluator = new EnforcementPolicyEvaluator(policy);

        var communitySignal = new BlackboxGuardSignal
        {
            IsAvailable = true,
            IsBlock = true,
            SignalId = "community-ioc-42",
            CommunityOnly = true,
        };

        var advisoryVerdict = evaluator.Evaluate(
            new AgentActionRequest
            {
                RequestId = "req-comm-1",
                AgentId = "opencode",
                Kind = AgentActionKind.NetworkConnect,
                Target = "unknown-community.example",
                UtcTime = Observed,
            },
            new EnforcementCapabilities
            {
                Strength = EnforcementStrength.HostHook,
                HostSupportsDeny = true,
            },
            communitySignal);

        Assert.Equal(EnforcementDecision.Audit, advisoryVerdict.Decision);
        Assert.Equal(EnforcementReasonCodes.CommunityAdvisoryOnly, advisoryVerdict.ReasonCode);

        var localBlockedVerdict = evaluator.Evaluate(
            new AgentActionRequest
            {
                RequestId = "req-comm-2",
                AgentId = "opencode",
                Kind = AgentActionKind.NetworkConnect,
                Target = "evil-local.example",
                UtcTime = Observed,
            },
            new EnforcementCapabilities
            {
                Strength = EnforcementStrength.HostHook,
                HostSupportsDeny = true,
            },
            communitySignal);

        Assert.Equal(EnforcementDecision.Block, localBlockedVerdict.Decision);
        Assert.Equal(EnforcementReasonCodes.RuleBlock, localBlockedVerdict.ReasonCode);
    }

    private static EnforcementReceiptV1 MakeReceipt(string eventId, EnforcementReceiptResult result) =>
        EnforcementReceiptV1.Create(
            eventId: eventId,
            requestId: "req-" + eventId,
            policyRevision: "rev-1",
            hostAdapter: "opencode",
            hostVersion: "2.0",
            actionKind: AgentActionKind.ReadFile,
            decisionSource: "local_policy",
            rawTargetOrIndicator: @"C:\lab\file.txt",
            requestedDecision: EnforcementDecision.Block,
            boundary: EnforcementBoundaryKind.HostHook,
            result: result,
            observedSideEffect: EnforcementObservedSideEffect.Unknown,
            verifiedBy: null,
            timestampUtc: Observed);
}
