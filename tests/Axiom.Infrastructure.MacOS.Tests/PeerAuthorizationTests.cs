// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Protection;
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Infrastructure.MacOS.Ipc;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class PeerAuthorizationTests
{
    private static readonly PeerPolicy OwnerAndAdmins = new(501, true, uid => uid == 502);

    [Theory]
    [InlineData(0u, "uid:0")]
    [InlineData(501u, "uid:501")]
    [InlineData(502u, "uid:502")]
    [InlineData(1000u, "uid:1000")]
    public void RootAndConsoleUsersAreAllowed(uint uid, string actor)
    {
        var decision = PeerAuthorization.Decide(uid);

        Assert.True(decision.Allowed);
        Assert.True(decision.CanWrite);
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
        Assert.False(decision.CanWrite);
        Assert.Equal("uid:" + uid, decision.Actor);
        Assert.False(string.IsNullOrWhiteSpace(decision.Reason));
        Assert.False(PeerAuthorization.Decide(uid, OwnerAndAdmins).Allowed);
    }

    [Fact]
    public void UnknownPeerIsRejected()
    {
        Assert.False(PeerAuthorization.Decide(null).Allowed);
        Assert.False(PeerAuthorization.Decide(uint.MaxValue).Allowed);
        Assert.Equal("uid:unknown", PeerAuthorization.Decide(null).Actor);
    }

    [Fact]
    public void RootOwnerAndAdminMembersMayWrite()
    {
        Assert.True(PeerAuthorization.Decide(0, OwnerAndAdmins) is { Allowed: true, CanWrite: true, Reason: "root" });
        Assert.True(PeerAuthorization.Decide(501, OwnerAndAdmins) is { Allowed: true, CanWrite: true, Reason: "installing user" });
        Assert.True(PeerAuthorization.Decide(502, OwnerAndAdmins) is { Allowed: true, CanWrite: true, Reason: "admin group member" });
    }

    [Fact]
    public void OtherConsoleUsersMayOnlyRead()
    {
        var decision = PeerAuthorization.Decide(503, OwnerAndAdmins);

        Assert.True(decision.Allowed);
        Assert.False(decision.CanWrite);
        Assert.Equal("uid:503", decision.Actor);
        Assert.NotNull(decision.WriteDenialReason);
        Assert.Contains("uid 501", decision.WriteDenialReason, StringComparison.Ordinal);
        Assert.Contains("admin group", decision.WriteDenialReason, StringComparison.Ordinal);
        Assert.Contains("uid 503 may only read", decision.WriteDenialReason, StringComparison.Ordinal);
    }

    [Fact]
    public void AdminGroupCanBeSwitchedOffAndOwnerMayBeAbsent()
    {
        var ownerOnly = new PeerPolicy(501, false, _ => true);
        Assert.True(PeerAuthorization.Decide(501, ownerOnly).CanWrite);
        Assert.False(PeerAuthorization.Decide(502, ownerOnly).CanWrite);
        Assert.DoesNotContain("admin group", PeerAuthorization.Decide(502, ownerOnly).WriteDenialReason, StringComparison.Ordinal);

        Assert.False(PeerAuthorization.Decide(501, PeerPolicy.RootOnlyWrites).CanWrite);
        Assert.True(PeerAuthorization.Decide(0, PeerPolicy.RootOnlyWrites).CanWrite);
        Assert.Contains("only allowed for root;", PeerAuthorization.Decide(501, PeerPolicy.RootOnlyWrites).WriteDenialReason, StringComparison.Ordinal);
    }

    [Fact]
    public void PolicyComesFromProtectionSettings()
    {
        var settings = new ProtectionSettings { AllowedUid = 777, AllowAdminGroupWrites = false };
        var policy = PeerPolicy.FromSettings(settings, _ => true);

        Assert.Equal(777u, policy.OwnerUid);
        Assert.False(policy.AdminGroupMayWrite);
        Assert.True(new ProtectionSettings().AllowAdminGroupWrites);
        Assert.Null(new ProtectionSettings().AllowedUid);
    }

    [Fact]
    public void GroupMembershipIsReadFromLibc()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Assert.False(UnixGroups.IsMember(uint.MaxValue - 1, "no-such-group-axiom"));
        Assert.False(UnixGroups.IsMember(0, "no-such-group-axiom"));

        // root is always in its primary group (root on Linux, wheel on macOS).
        Assert.True(UnixGroups.IsMember(0, OperatingSystem.IsMacOS() ? "wheel" : "root"));
    }
}
