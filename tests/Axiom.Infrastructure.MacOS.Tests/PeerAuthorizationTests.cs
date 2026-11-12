// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Core.Protection;
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Infrastructure.MacOS.Ipc;
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.MacOS.Tests;

/// <summary>
/// The IPC authorization policy (GitHub review 2026-11-12, P0 #1): a second local user must not
/// read machine-wide activity, only root, the installing user and (by explicit policy) admins may.
/// </summary>
public sealed class PeerAuthorizationTests
{
    private static readonly PeerPolicy OwnerAndAdmins = new(501, true, uid => uid == 502);

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

    [Theory]
    [InlineData(0u, "uid:0")]
    [InlineData(501u, "uid:501")]
    [InlineData(502u, "uid:502")]
    [InlineData(1000u, "uid:1000")]
    public void RootAndConsoleUsersMayConnect(uint uid, string actor)
    {
        var decision = PeerAuthorization.Decide(uid);

        Assert.True(decision.Allowed);
        Assert.Equal(actor, decision.Actor);
        // Without an install record only root is privileged; a console user gets public health only.
        Assert.Equal(uid == 0, decision.CanWrite);
        Assert.Equal(uid == 0, decision.CanReadPrivate);
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
        Assert.False(decision.CanReadPrivate);
        Assert.Equal("uid:" + uid, decision.Actor);
        Assert.False(string.IsNullOrWhiteSpace(decision.Reason));
        Assert.False(PeerAuthorization.Decide(uid, OwnerAndAdmins).Allowed);
        foreach (var commandClass in Enum.GetValues<IpcCommandClass>())
        {
            Assert.False(PeerAuthorization.Permits(uid, OwnerAndAdmins, commandClass));
        }
    }

    [Fact]
    public void UnknownPeerCredentialsAreRejectedForEveryCommandClass()
    {
        Assert.False(PeerAuthorization.Decide(null).Allowed);
        Assert.False(PeerAuthorization.Decide(uint.MaxValue).Allowed);
        Assert.Equal("uid:unknown", PeerAuthorization.Decide(null).Actor);
        foreach (var commandClass in Enum.GetValues<IpcCommandClass>())
        {
            Assert.False(PeerAuthorization.Permits(null, OwnerAndAdmins, commandClass));
            Assert.False(PeerAuthorization.Permits(uint.MaxValue, OwnerAndAdmins, commandClass));
        }
    }

    [Fact]
    public void RootFollowsTheDocumentedPrivilegedPolicy()
    {
        var root = PeerAuthorization.Decide(0, OwnerAndAdmins);
        Assert.True(root is { Allowed: true, CanWrite: true, CanReadPrivate: true, Reason: "root" });
        Assert.True(PeerAuthorization.Decide(0, PeerPolicy.RootOnlyWrites) is { CanWrite: true, CanReadPrivate: true });
        foreach (var commandClass in Enum.GetValues<IpcCommandClass>())
        {
            Assert.True(PeerAuthorization.Permits(0, PeerPolicy.RootOnlyWrites, commandClass));
        }
    }

    [Fact]
    public void InstallingUserReadsPrivateDataAndWrites()
    {
        var owner = PeerAuthorization.Decide(501, OwnerAndAdmins);

        Assert.True(owner is { Allowed: true, CanWrite: true, CanReadPrivate: true, Reason: "installing user" });
        foreach (var command in PrivateReads)
        {
            Assert.True(owner.ToCaller().Permits(IpcCommandAccess.Classify(command)), command);
        }

        Assert.True(owner.ToCaller().Permits(IpcCommandAccess.Classify(IpcCommandTypes.RuleApply)));
    }

    [Fact]
    public void AdminGroupMemberIsPrivilegedOnlyUnderTheExplicitPolicy()
    {
        var admin = PeerAuthorization.Decide(502, OwnerAndAdmins);
        Assert.True(admin is { Allowed: true, CanWrite: true, CanReadPrivate: true });
        Assert.Contains("AllowAdminGroupWrites", admin.Reason, StringComparison.Ordinal);

        var policyOff = new PeerPolicy(501, false, _ => true);
        var denied = PeerAuthorization.Decide(502, policyOff);
        Assert.True(denied is { Allowed: true, CanWrite: false, CanReadPrivate: false });
        Assert.DoesNotContain("admin group", denied.WriteDenialReason, StringComparison.Ordinal);
        Assert.DoesNotContain("admin group", denied.ReadDenialReason, StringComparison.Ordinal);
    }

    /// <summary>A second standard user (uid 503 here, 502 on the VM) gets public health and nothing else.</summary>
    [Fact]
    public void OtherConsoleUsersGetPublicHealthOnly()
    {
        var decision = PeerAuthorization.Decide(503, OwnerAndAdmins);

        Assert.True(decision.Allowed);
        Assert.False(decision.CanWrite);
        Assert.False(decision.CanReadPrivate);
        Assert.Equal("uid:503", decision.Actor);
        Assert.NotNull(decision.WriteDenialReason);
        Assert.NotNull(decision.ReadDenialReason);
        Assert.Contains("uid 501", decision.ReadDenialReason, StringComparison.Ordinal);
        Assert.Contains("admin group", decision.ReadDenialReason, StringComparison.Ordinal);
        Assert.Contains("uid 503 may only read public service health", decision.ReadDenialReason, StringComparison.Ordinal);
        Assert.Contains("uid 503 may only read public service health", decision.WriteDenialReason, StringComparison.Ordinal);

        var caller = decision.ToCaller();
        Assert.True(caller.Permits(IpcCommandAccess.Classify(IpcCommandTypes.ServiceHealth)));
        Assert.True(caller.Permits(IpcCommandAccess.Classify(IpcCommandTypes.Capabilities)));
        foreach (var command in PrivateReads)
        {
            Assert.False(caller.Permits(IpcCommandAccess.Classify(command)), command + " must be private");
        }

        foreach (var command in IpcCommandAccess.WriteCommands)
        {
            Assert.False(caller.Permits(IpcCommandAccess.Classify(command)), command + " must be denied");
        }

        Assert.False(caller.Permits(IpcCommandAccess.Classify("something.new")));
        Assert.False(PeerAuthorization.Permits(503, OwnerAndAdmins, IpcCommandClass.PrivateRead));
        Assert.True(PeerAuthorization.Permits(503, OwnerAndAdmins, IpcCommandClass.PublicRead));
    }

    [Fact]
    public void OwnerMayBeAbsent()
    {
        Assert.False(PeerAuthorization.Decide(501, PeerPolicy.RootOnlyWrites).CanWrite);
        Assert.False(PeerAuthorization.Decide(501, PeerPolicy.RootOnlyWrites).CanReadPrivate);
        Assert.Contains("only allowed for root;", PeerAuthorization.Decide(501, PeerPolicy.RootOnlyWrites).WriteDenialReason, StringComparison.Ordinal);
        Assert.Contains("only allowed for root;", PeerAuthorization.Decide(501, PeerPolicy.RootOnlyWrites).ReadDenialReason, StringComparison.Ordinal);
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
    public void PublicHealthCarriesNoActivityPathsOrErrors()
    {
        var health = new ServiceHealth
        {
            Status = "running",
            UptimeSeconds = 10,
            SourceName = "libproc",
            PollIntervalSeconds = 2,
            LastCaptureUtc = DateTimeOffset.UtcNow,
            ConnectionCount = 17,
            ProcessCount = 9,
            Limitations = ["/Applications/Secret.app could not be resolved", "adapter en0 10.0.0.5"],
            LastError = "open /Library/Application Support/Axiom/axiom.db failed",
        };

        var redacted = IpcCommandAccess.RedactHealth(health);

        Assert.Equal("running", redacted.Status);
        Assert.Equal(10, redacted.UptimeSeconds);
        Assert.Null(redacted.LastCaptureUtc);
        Assert.Equal(0, redacted.ConnectionCount);
        Assert.Equal(0, redacted.ProcessCount);
        Assert.Null(redacted.LastError);
        Assert.Equal([IpcCommandAccess.HealthRedactedNote], redacted.Limitations);
        var text = System.Text.Json.JsonSerializer.Serialize(redacted, IpcJson.Options);
        Assert.DoesNotContain("/Applications", text, StringComparison.Ordinal);
        Assert.DoesNotContain("axiom.db", text, StringComparison.Ordinal);
        Assert.DoesNotContain("10.0.0.5", text, StringComparison.Ordinal);
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
