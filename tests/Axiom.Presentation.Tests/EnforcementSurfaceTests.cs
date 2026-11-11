// SPDX-License-Identifier: GPL-3.0-or-later
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
}
