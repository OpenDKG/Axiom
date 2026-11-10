// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.MacOS.Ipc;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class PeerAuthorizationTests
{
    [Theory]
    [InlineData(0u, "uid:0")]
    [InlineData(501u, "uid:501")]
    [InlineData(502u, "uid:502")]
    [InlineData(1000u, "uid:1000")]
    public void RootAndConsoleUsersAreAllowed(uint uid, string actor)
    {
        var decision = PeerAuthorization.Decide(uid);

        Assert.True(decision.Allowed);
        Assert.Equal(actor, decision.Actor);
    }

    [Theory]
    [InlineData(1u)]
    [InlineData(55u)]
    [InlineData(248u)]
    [InlineData(500u)]
    [InlineData(4294967294u)]
    public void SystemAccountsAndNobodyAreRejected(uint uid)
    {
        var decision = PeerAuthorization.Decide(uid);

        Assert.False(decision.Allowed);
        Assert.Equal("uid:" + uid, decision.Actor);
        Assert.False(string.IsNullOrWhiteSpace(decision.Reason));
    }

    [Fact]
    public void UnknownPeerIsRejected()
    {
        Assert.False(PeerAuthorization.Decide(null).Allowed);
        Assert.False(PeerAuthorization.Decide(uint.MaxValue).Allowed);
        Assert.Equal("uid:unknown", PeerAuthorization.Decide(null).Actor);
    }
}
