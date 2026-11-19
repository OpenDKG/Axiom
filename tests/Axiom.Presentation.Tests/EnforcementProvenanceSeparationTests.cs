// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

/// <summary>
/// The shield level (network filter acknowledgement) and the agent enforcement surface (hook,
/// host deny, OS deny receipts) are separate facts: a filter ack never promotes the agent surface.
/// </summary>
public sealed class EnforcementProvenanceSeparationTests
{
    [Fact]
    public void Filter_acknowledgement_is_not_an_os_deny_receipt()
    {
        // The shield is green because the filter acknowledged the rules ...
        Assert.Equal(EnforcementLevel.Protected, ShieldProtection.Level(known: true, enabled: true, enforcementVerified: true));

        // ... but without receipts the agent surface stays cooperative and claims no verified block.
        var agent = EnforcementSurfaceState.FromReceiptsAndStatus(status: null, receipts: null);
        Assert.Equal(EnforcementVerification.Cooperative, agent.Verification);
        Assert.False(agent.CanClaimVerifiedBlocking);
        Assert.NotEqual(EnforcementLevel.Protected, agent.Level);
    }

    [Fact]
    public void Unreachable_daemon_is_unknown_never_green()
    {
        Assert.Null(ShieldProtection.Level(known: false, enabled: true, enforcementVerified: true));
        Assert.Equal("idle", ShieldProtection.Tone(null));
        Assert.NotEqual(ShieldProtection.ProtectedColor, ShieldProtection.LampColor(null));
    }
}
