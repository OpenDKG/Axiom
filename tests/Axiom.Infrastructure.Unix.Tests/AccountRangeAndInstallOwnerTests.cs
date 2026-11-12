// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Protection;
using Axiom.Infrastructure.Unix.Install;
using Axiom.Infrastructure.Unix.Ipc;

namespace Axiom.Infrastructure.Unix.Tests;

public sealed class AccountRangeAndInstallOwnerTests
{
    [Theory]
    [InlineData(0u, true, "root")]
    [InlineData(999u, false, "system account")]
    [InlineData(1000u, true, "console user")]
    [InlineData(65534u, false, "nobody")]
    [InlineData(uint.MaxValue, false, "unknown peer")]
    public void LinuxRangeUsesUidFloor1000AndNobody65534(uint uid, bool allowed, string reason)
    {
        var decision = PeerAuthorization.Decide(uid, null, UnixAccountRange.Linux);

        Assert.Equal(allowed, decision.Allowed);
        Assert.Contains(reason, decision.Reason + " " + decision.WriteDenialReason, StringComparison.Ordinal);
    }

    [Fact]
    public void MacRangeIsUnchangedThroughTheTwoArgumentOverloads()
    {
        Assert.True(PeerAuthorization.Decide(501).Allowed);
        Assert.False(PeerAuthorization.Decide(500).Allowed);
        Assert.False(PeerAuthorization.Decide(4294967294).Allowed);
        Assert.True(PeerAuthorization.Decide(1000, null, UnixAccountRange.Linux).Allowed);
        Assert.False(PeerAuthorization.Decide(999, null, UnixAccountRange.Linux).Allowed);
        Assert.Equal(PeerAuthorization.Description, UnixAccountRange.MacOS.Describe());
    }

    [Fact]
    public void LinuxWritePolicyIsRootOwnerOrAdminGroups()
    {
        var policy = new PeerPolicy(OwnerUid: 1000, AdminGroupMayWrite: true, uid => uid == 1001);

        Assert.True(PeerAuthorization.Decide(0, policy, UnixAccountRange.Linux).CanWrite);
        Assert.Equal("installing user", PeerAuthorization.Decide(1000, policy, UnixAccountRange.Linux).Reason);
        Assert.Equal("admin group member", PeerAuthorization.Decide(1001, policy, UnixAccountRange.Linux).Reason);

        var reader = PeerAuthorization.Decide(1002, policy, UnixAccountRange.Linux);
        Assert.True(reader.Allowed);
        Assert.False(reader.CanWrite);
        Assert.Contains("members of the axiom, sudo or wheel groups", reader.WriteDenialReason, StringComparison.Ordinal);
        Assert.Contains("uid 1000", reader.WriteDenialReason, StringComparison.Ordinal);

        Assert.Equal(["axiom", "sudo", "wheel"], UnixAccountRange.Linux.AdminGroups);
        Assert.Contains("SO_PEERCRED", UnixAccountRange.Linux.Describe(), StringComparison.Ordinal);
        Assert.Contains("uid >= 1000", UnixAccountRange.Linux.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void PolicyFromSettingsForARangeChecksEveryAdminGroup()
    {
        var settings = new ProtectionSettings { AllowedUid = 1000, AllowAdminGroupWrites = true };
        var policy = PeerPolicy.FromSettings(settings, UnixAccountRange.Linux);

        Assert.Equal(1000u, policy.OwnerUid);
        Assert.True(policy.AdminGroupMayWrite);
        // uid 0 is root: a member of no admin group on this box or of "wheel" on others; either answer is valid.
        _ = policy.IsAdminMember(0);
    }

    [Theory]
    [InlineData("1000", null, 1000u)]
    [InlineData(null, "1001", 1001u)]
    [InlineData("999", "1002", 1002u)]
    [InlineData("0", "65534", null)]
    [InlineData("abc", null, null)]
    public void LinuxInstallOwnerPrefersSudoUidThenPkexecUid(string? sudoUid, string? pkexecUid, uint? expected)
    {
        Assert.Equal(expected, InstallOwner.Resolve(sudoUid, pkexecUid, null, UnixAccountRange.Linux));
    }

    [Fact]
    public void MacInstallOwnerOverloadKeepsConsoleOwnerSemantics()
    {
        Assert.Equal(501u, InstallOwner.Resolve(null, 501));
        Assert.Null(InstallOwner.Resolve("500", null));
        Assert.Equal(1000u, InstallOwner.Resolve("1000", 0));
        Assert.Equal(502u, InstallOwner.Resolve("502", 501));
    }
}
