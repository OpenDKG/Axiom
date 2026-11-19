// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Infrastructure.Unix.Ipc;
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.Unix.Tests;

/// <summary>
/// The three upstream enforcement commands (#322) under the Linux account range: none is public
/// health data; root and the install owner are permitted, every other uid (a second desktop user,
/// a member of the admin group that may write rules, a system account) is not, because decisions,
/// receipts and policy paths belong to the installing user.
/// </summary>
public sealed class LinuxEnforcementCommandAuthorizationTests
{
    private static readonly PeerPolicy OwnerAndAdmins = new(1000, true, uid => uid == 1001);

    private static readonly PeerPolicy OwnerOnly = new(1000, false, _ => false);

    [Theory]
    [InlineData(IpcCommandTypes.EnforcementStatus, IpcCommandClass.PrivateRead)]
    [InlineData(IpcCommandTypes.EnforcementReceipts, IpcCommandClass.PrivateRead)]
    [InlineData(IpcCommandTypes.EnforcementEvaluate, IpcCommandClass.Write)]
    public void EnforcementCommandsAreNeverPublic(string command, IpcCommandClass expected)
    {
        Assert.Equal(expected, IpcCommandAccess.Classify(command));
        Assert.NotEqual(IpcCommandClass.PublicRead, IpcCommandAccess.Classify(command));
    }

    [Theory]
    [InlineData(IpcCommandTypes.EnforcementStatus, 0u, true)]
    [InlineData(IpcCommandTypes.EnforcementStatus, 1000u, true)]
    [InlineData(IpcCommandTypes.EnforcementStatus, 1002u, false)]
    [InlineData(IpcCommandTypes.EnforcementReceipts, 0u, true)]
    [InlineData(IpcCommandTypes.EnforcementReceipts, 1000u, true)]
    [InlineData(IpcCommandTypes.EnforcementReceipts, 1002u, false)]
    [InlineData(IpcCommandTypes.EnforcementEvaluate, 0u, true)]
    [InlineData(IpcCommandTypes.EnforcementEvaluate, 1000u, true)]
    [InlineData(IpcCommandTypes.EnforcementEvaluate, 1002u, false)]
    public void RootAndOwnerArePermittedAnotherUserIsNot(string command, uint uid, bool permitted)
    {
        var commandClass = IpcCommandAccess.Classify(command);

        foreach (var policy in new[] { OwnerOnly, OwnerAndAdmins })
        {
            var decision = PeerAuthorization.Decide(uid, policy, UnixAccountRange.Linux);

            Assert.True(decision.Allowed);
            Assert.Equal(permitted, decision.ToCaller().Permits(commandClass));
        }
    }

    /// <summary>Without an install record only root may use them.</summary>
    [Theory]
    [InlineData(IpcCommandTypes.EnforcementStatus)]
    [InlineData(IpcCommandTypes.EnforcementReceipts)]
    [InlineData(IpcCommandTypes.EnforcementEvaluate)]
    public void WithoutAnInstallOwnerOnlyRootIsPermitted(string command)
    {
        var commandClass = IpcCommandAccess.Classify(command);

        Assert.True(PeerAuthorization.Decide(0, null, UnixAccountRange.Linux).ToCaller().Permits(commandClass));
        Assert.False(PeerAuthorization.Decide(1000, null, UnixAccountRange.Linux).ToCaller().Permits(commandClass));
    }
}
