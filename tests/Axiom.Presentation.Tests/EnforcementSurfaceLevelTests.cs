// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class EnforcementSurfaceLevelTests
{
    [Fact]
    public void Default_state_is_degraded()
    {
        Assert.Equal(EnforcementLevel.Degraded, EnforcementSurfaceState.Current.Level);
        Assert.True(EnforcementSurfaceState.Current.IsDegraded);
    }

    [Fact]
    public void Unavailable_guard_is_unprotected()
    {
        var state = EnforcementSurfaceState.FromReceiptsAndStatus(
            status: null,
            receipts: null,
            guardAvailable: false);

        Assert.True(state.IsUnprotected);
        Assert.Equal("Not protected", state.LevelText);
    }

    [Fact]
    public void Blocking_hooks_with_an_enabled_policy_are_protected()
    {
        var state = EnforcementSurfaceState.FromReceiptsAndStatus(
            new EnforcementStatusDto
            {
                Enabled = true,
                Revision = "1",
                AgentCount = 11,
                RuleCount = 88,
                ProtectedResourceCount = 8,
            },
            receipts: null,
            guardAvailable: true,
            hostHookMode: "block");

        Assert.True(state.IsProtected);
        Assert.Equal("Protected", state.LevelText);
        Assert.Equal("HOOK BLOCKING ACTIVE", state.VerificationLabel);
    }

    [Fact]
    public void Policy_error_is_unprotected()
    {
        var state = EnforcementSurfaceState.FromReceiptsAndStatus(
            new EnforcementStatusDto
            {
                Enabled = false,
                Revision = "1",
                AgentCount = 0,
                RuleCount = 0,
                ProtectedResourceCount = 0,
                Error = "policy.json is unreadable",
            },
            receipts: null,
            guardAvailable: true,
            hostHookMode: "block");

        Assert.True(state.IsUnprotected);
    }

    [Fact]
    public void Audit_mode_is_unprotected()
    {
        var state = EnforcementSurfaceState.FromReceiptsAndStatus(
            new EnforcementStatusDto
            {
                Enabled = true,
                Revision = "1",
                AgentCount = 11,
                RuleCount = 88,
                ProtectedResourceCount = 8,
            },
            receipts: null,
            guardAvailable: true,
            hostHookMode: "audit");

        Assert.True(state.IsUnprotected);
        Assert.False(state.IsProtected);
    }
}
