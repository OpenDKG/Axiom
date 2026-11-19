// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Core.Protection;
using Axiom.Infrastructure.Unix.Ipc;
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.Unix.Tests;

/// <summary>
/// Linux flavour of the macOS review P0 #1 policy (docs/LINUX_ARCHITECTURE.md authorization
/// table): the same pure <see cref="PeerAuthorization.Decide(uint?, PeerPolicy?, UnixAccountRange)"/>
/// with the three command classes, SO_PEERCRED uids and the 1000 / 65534 account range.
/// </summary>
public sealed class LinuxPeerAuthorizationTests
{
    private static readonly PeerPolicy OwnerAndAdmins = new(1000, true, uid => uid == 1001);

    private static readonly PeerPolicy OwnerOnly = new(1000, false, uid => uid == 1001);

    private static readonly string[] PrivateReads =
    [
        IpcCommandTypes.Snapshot,
        IpcCommandTypes.LiveEvents,
        IpcCommandTypes.HistoryQuery,
        IpcCommandTypes.ThroughputHistory,
        IpcCommandTypes.DiagnosticsExport,
        IpcCommandTypes.PrivacyStatus,
        IpcCommandTypes.ThreatShareStatus,
        IpcCommandTypes.ProtectionStatus,
        IpcCommandTypes.ConfigGet,
        IpcCommandTypes.RulesQuery,
        IpcCommandTypes.RuleVerify,
    ];

    [Fact]
    public void RootIsPrivilegedWithoutAnyInstallRecord()
    {
        var decision = PeerAuthorization.Decide(0, null, UnixAccountRange.Linux);

        Assert.True(decision.Allowed);
        Assert.True(decision.CanReadPrivate);
        Assert.True(decision.CanWrite);
        Assert.Equal("root", decision.Reason);
        foreach (var commandClass in Enum.GetValues<IpcCommandClass>())
        {
            Assert.True(PeerAuthorization.Permits(0, null, commandClass, UnixAccountRange.Linux));
        }
    }

    [Fact]
    public void InstallingUidGetsEveryClass()
    {
        var decision = PeerAuthorization.Decide(1000, OwnerAndAdmins, UnixAccountRange.Linux);

        Assert.True(decision.Allowed);
        Assert.True(decision.CanReadPrivate);
        Assert.True(decision.CanWrite);
        Assert.Equal("installing user", decision.Reason);
        Assert.Equal("uid:1000", decision.Actor);
        foreach (var command in PrivateReads.Concat(IpcCommandAccess.WriteCommands))
        {
            Assert.True(decision.ToCaller().Permits(IpcCommandAccess.Classify(command)), command);
        }
    }

    [Fact]
    public void AdminGroupMembersFollowTheSamePolicyFlagAsMacOS()
    {
        // Default policy (AllowAdminGroupWrites = true): axiom/sudo/wheel members read private data and write.
        var admin = PeerAuthorization.Decide(1001, OwnerAndAdmins, UnixAccountRange.Linux);
        Assert.True(admin.CanReadPrivate);
        Assert.True(admin.CanWrite);
        Assert.Equal("admin group member (AllowAdminGroupWrites)", admin.Reason);

        // Flag off: the same member is a public-only user; nothing else changes.
        var demoted = PeerAuthorization.Decide(1001, OwnerOnly, UnixAccountRange.Linux);
        Assert.True(demoted.Allowed);
        Assert.False(demoted.CanReadPrivate);
        Assert.False(demoted.CanWrite);
        Assert.Contains("only allowed for root, the user who installed Axiom (uid 1000);", demoted.ReadDenialReason, StringComparison.Ordinal);
        Assert.DoesNotContain("groups", demoted.ReadDenialReason, StringComparison.Ordinal);
        Assert.True(new ProtectionSettings().AllowAdminGroupWrites);
    }

    [Fact]
    public void OtherUidsGetPublicHealthOnly()
    {
        var decision = PeerAuthorization.Decide(1002, OwnerAndAdmins, UnixAccountRange.Linux);

        Assert.True(decision.Allowed);
        Assert.False(decision.CanReadPrivate);
        Assert.False(decision.CanWrite);
        Assert.Equal("console user (public health only)", decision.Reason);
        Assert.Contains("uid 1002 may only read public service health", decision.ReadDenialReason, StringComparison.Ordinal);
        Assert.Contains("members of the axiom, sudo or wheel groups", decision.ReadDenialReason, StringComparison.Ordinal);
        Assert.Contains("discloses machine-wide activity", decision.ReadDenialReason, StringComparison.Ordinal);
        Assert.Contains("changes machine-wide settings", decision.WriteDenialReason, StringComparison.Ordinal);

        var caller = decision.ToCaller();
        Assert.True(caller.Permits(IpcCommandAccess.Classify(IpcCommandTypes.ServiceHealth)));
        Assert.True(caller.Permits(IpcCommandAccess.Classify(IpcCommandTypes.Capabilities)));
        Assert.Equal(IpcCommandClass.PublicRead, IpcCommandAccess.Classify(IpcCommandTypes.ServiceHealth));
        Assert.Equal(IpcCommandClass.PublicRead, IpcCommandAccess.Classify(IpcCommandTypes.Capabilities));
        foreach (var command in PrivateReads)
        {
            Assert.Equal(IpcCommandClass.PrivateRead, IpcCommandAccess.Classify(command));
            Assert.False(caller.Permits(IpcCommandClass.PrivateRead), command);
        }

        foreach (var command in IpcCommandAccess.WriteCommands)
        {
            Assert.Equal(IpcCommandClass.Write, IpcCommandAccess.Classify(command));
            Assert.False(caller.Permits(IpcCommandClass.Write), command);
        }

        Assert.Equal(IpcCommandClass.Write, IpcCommandAccess.Classify("something.new"));
        Assert.True(PeerAuthorization.Permits(1002, OwnerAndAdmins, IpcCommandClass.PublicRead, UnixAccountRange.Linux));
        Assert.False(PeerAuthorization.Permits(1002, OwnerAndAdmins, IpcCommandClass.PrivateRead, UnixAccountRange.Linux));
        Assert.False(PeerAuthorization.Permits(1002, OwnerAndAdmins, IpcCommandClass.Write, UnixAccountRange.Linux));
    }

    [Theory]
    [InlineData(1u)]
    [InlineData(999u)]
    [InlineData(65534u)]
    [InlineData(uint.MaxValue)]
    public void SystemAccountsNobodyAndUnknownCredentialsAreRejected(uint uid)
    {
        var decision = PeerAuthorization.Decide(uid, OwnerAndAdmins, UnixAccountRange.Linux);

        Assert.False(decision.Allowed);
        Assert.False(decision.CanReadPrivate);
        Assert.False(decision.CanWrite);
        foreach (var commandClass in Enum.GetValues<IpcCommandClass>())
        {
            Assert.False(PeerAuthorization.Permits(uid, OwnerAndAdmins, commandClass, UnixAccountRange.Linux));
        }

        Assert.False(PeerAuthorization.Decide(null, OwnerAndAdmins, UnixAccountRange.Linux).Allowed);
        Assert.Equal("uid:unknown", PeerAuthorization.Decide(null, OwnerAndAdmins, UnixAccountRange.Linux).Actor);
    }

    [Fact]
    public void WithoutAnInstallRecordOnlyRootIsPrivileged()
    {
        var owner = PeerAuthorization.Decide(1000, PeerPolicy.RootOnlyWrites, UnixAccountRange.Linux);

        Assert.True(owner.Allowed);
        Assert.False(owner.CanReadPrivate);
        Assert.False(owner.CanWrite);
        Assert.Contains("only allowed for root;", owner.ReadDenialReason, StringComparison.Ordinal);
    }

    [Fact]
    public void PublicHealthIsRedactedForPublicOnlyCallers()
    {
        var health = new ServiceHealth
        {
            Status = "running",
            UptimeSeconds = 10,
            SourceName = "proc",
            PollIntervalSeconds = 2,
            ConnectionCount = 17,
            ProcessCount = 9,
            Limitations = ["/home/alice/secret-app could not be resolved"],
            LastError = "open /var/lib/axiom/axiom.db failed",
        };

        var redacted = IpcCommandAccess.RedactHealth(health);

        Assert.Equal(0, redacted.ConnectionCount);
        Assert.Null(redacted.LastError);
        Assert.Equal([IpcCommandAccess.HealthRedactedNote], redacted.Limitations);
        Assert.DoesNotContain("/home/alice", System.Text.Json.JsonSerializer.Serialize(redacted, IpcJson.Options), StringComparison.Ordinal);
    }
}
