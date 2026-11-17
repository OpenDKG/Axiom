// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

/// <summary>The network lamp and the agent enforcement surface share one level vocabulary.</summary>
public sealed class ProtectionLampLevelTests
{
    [Theory]
    [InlineData(false, false, false, EnforcementLevel.Unknown)]
    [InlineData(false, true, true, EnforcementLevel.Unknown)]
    [InlineData(true, false, false, EnforcementLevel.Unprotected)]
    [InlineData(true, false, true, EnforcementLevel.Unprotected)]
    [InlineData(true, true, false, EnforcementLevel.Degraded)]
    [InlineData(true, true, true, EnforcementLevel.Protected)]
    public void Network_lamp_is_green_only_when_answered_on_and_confirmed(
        bool answered, bool shieldOn, bool confirmed, EnforcementLevel expected)
    {
        Assert.Equal(expected, ProtectionLamp.ForNetwork(answered, shieldOn, confirmed));
    }

    [Fact]
    public void Each_level_has_its_own_lamp_colour()
    {
        Assert.Equal(ProtectionLamp.ProtectedColor, ProtectionLamp.ColorFor(EnforcementLevel.Protected));
        Assert.Equal(ProtectionLamp.DegradedColor, ProtectionLamp.ColorFor(EnforcementLevel.Degraded));
        Assert.Equal(ProtectionLamp.UnprotectedColor, ProtectionLamp.ColorFor(EnforcementLevel.Unprotected));
        Assert.Equal(ProtectionLamp.UnknownColor, ProtectionLamp.ColorFor(EnforcementLevel.Unknown));
    }

    [Fact]
    public void Without_receipts_the_agent_surface_never_claims_os_verified_blocking()
    {
        // A macOS/Linux network-filter acknowledgement is not an OS_DENY_VERIFIED receipt; with no
        // receipts the agent surface must stay cooperative whatever the network lamp shows.
        var state = EnforcementSurfaceState.FromReceiptsAndStatus(status: null, receipts: null);

        Assert.Equal(EnforcementVerification.Cooperative, state.Verification);
        Assert.False(state.CanClaimVerifiedBlocking);
        Assert.NotEqual(EnforcementLevel.Protected, state.Level);
    }
}
