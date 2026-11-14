// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class EnforcementSurfaceTests
{
    [Fact]
    public void Current_state_is_cooperative_and_claims_nothing_verified()
    {
        var state = EnforcementSurfaceState.Current;

        Assert.Equal(EnforcementVerification.Cooperative, state.Verification);
        Assert.False(state.CanClaimVerifiedBlocking);
        Assert.Contains("NOT VERIFIED", state.VerificationLabel, StringComparison.Ordinal);
    }

    [Fact]
    public void Current_text_never_advertises_verified_blocking()
    {
        var state = EnforcementSurfaceState.Current;
        var text = string.Join(
            '\n',
            state.VerificationLabel,
            state.Summary,
            state.DetectorDetail,
            state.BrokerDetail,
            state.PolicyDetail);

        Assert.DoesNotContain("VERIFIED BLOCKING", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not implemented", state.BrokerDetail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not wired", state.PolicyDetail, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(EnforcementVerification.HostDenyVerified)]
    [InlineData(EnforcementVerification.OsBoundaryVerified)]
    public void Only_a_proven_boundary_may_claim_verified_blocking(EnforcementVerification verification)
    {
        var state = EnforcementSurfaceState.Current with { Verification = verification };

        Assert.True(state.CanClaimVerifiedBlocking);
    }

    [Fact]
    public void Host_deny_sent_without_canary_verification_stays_cooperative_not_verified()
    {
        var status = new EnforcementStatusDto
        {
            Enabled = true,
            Revision = "rev-1",
            AgentCount = 1,
            RuleCount = 2,
            ProtectedResourceCount = 0,
            HostDenySentCount = 3,
            HostDenyVerifiedCount = 0,
        };

        var state = EnforcementSurfaceState.FromReceiptsAndStatus(status, guardAvailable: true);

        Assert.Equal(EnforcementVerification.Cooperative, state.Verification);
        Assert.False(state.CanClaimVerifiedBlocking);
        Assert.Equal("HOST_DENY_SENT - NOT VERIFIED", state.VerificationLabel);
        Assert.DoesNotContain("VERIFIED BLOCKING", state.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Guard_unavailable_reports_unprotected_truthfully()
    {
        var state = EnforcementSurfaceState.FromReceiptsAndStatus(status: null, guardAvailable: false);

        Assert.Equal(EnforcementVerification.Cooperative, state.Verification);
        Assert.False(state.CanClaimVerifiedBlocking);
        Assert.Equal("UNAVAILABLE - NOT PROTECTED", state.VerificationLabel);
    }

    [Fact]
    public void Canary_verified_receipt_unlocks_host_deny_verified_state()
    {
        var status = new EnforcementStatusDto
        {
            Enabled = true,
            Revision = "rev-1",
            AgentCount = 1,
            RuleCount = 2,
            ProtectedResourceCount = 0,
            HostDenySentCount = 1,
            HostDenyVerifiedCount = 1,
        };

        var state = EnforcementSurfaceState.FromReceiptsAndStatus(status, guardAvailable: true);

        Assert.Equal(EnforcementVerification.HostDenyVerified, state.Verification);
        Assert.True(state.CanClaimVerifiedBlocking);
        Assert.Equal("HOST_DENY_VERIFIED (CANARY)", state.VerificationLabel);
    }

    [Fact]
    public void Agent_evidence_event_derives_truthful_effective_channel()
    {
        var failed = new AgentEvidenceEvent(DateTimeOffset.UtcNow, "opencode", "GUARD_FAILED", "read", "", "error", 5, "bridge");
        var blocked = new AgentEvidenceEvent(DateTimeOffset.UtcNow, "claude", "GUARD_BLOCKED", "Bash", "block", "blocked", 8, "");
        var allowed = new AgentEvidenceEvent(DateTimeOffset.UtcNow, "codex", "GUARD_ALLOWED", "read", "allowed", "allowed", 3, "");

        Assert.Equal("FAILED_OPEN", failed.EffectiveChannel);
        Assert.Equal("HOST_DENY_SENT", blocked.EffectiveChannel);
        Assert.Equal("DETECTOR_ONLY", allowed.EffectiveChannel);
    }
}
