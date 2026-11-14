// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Core.Enforcement;
using Axiom.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class AgentFirewallEnforcerTests : IDisposable
{
    private const string Actor = "S-1-5-21-test";

    private static readonly DateTimeOffset Observed =
        new(2026, 11, 14, 6, 35, 0, TimeSpan.Zero);

    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "axiom-e4-tests",
        Guid.NewGuid().ToString("N"));

    private readonly FakeFirewallPolicyAdapter _adapter = new();
    private readonly HistoryStore _store;
    private readonly FirewallRuleCoordinator _coordinator;

    public AgentFirewallEnforcerTests()
    {
        _store = new HistoryStore(Path.Combine(_directory, "axiom.db"));
        _store.InitializeAsync(CancellationToken.None).GetAwaiter().GetResult();
        _coordinator = new FirewallRuleCoordinator(
            _adapter,
            _store,
            NullLogger<FirewallRuleCoordinator>.Instance);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public async Task Community_signal_is_refused_without_writing_any_firewall_rule()
    {
        var journal = new EnforcementReceiptJournal();
        var enforcer = new AgentFirewallEnforcer(_coordinator, journal, new FakeCanaryProbe());

        var outcome = await enforcer.ApplyScopedBlockAsync(
            new AgentFirewallRuleIntent
            {
                ExecutablePath = @"C:\Agents\opencode.exe",
                RemoteAddressOrCidr = "198.51.100.55",
                RemotePorts = "443",
                Origin = AgentNetworkPolicyOrigin.CommunitySignal,
                ExplicitlyAuthorizedByUser = false,
                ActorSid = Actor,
                PolicyRevision = "rev-1",
            },
            "req-comm-e4",
            Observed,
            CancellationToken.None);

        Assert.False(outcome.Applied);
        Assert.Equal(EnforcementReasonCodes.CommunityAdvisoryOnly, outcome.ErrorCode);
        Assert.Equal(EnforcementReceiptResult.AuditOnly, outcome.Receipt.Result);
        Assert.Equal(0, _adapter.UpsertCalls);
    }

    [Fact]
    public async Task Rule_write_and_readback_ack_never_claims_os_deny_verified()
    {
        var journal = new EnforcementReceiptJournal();
        var enforcer = new AgentFirewallEnforcer(_coordinator, journal, new FakeCanaryProbe());

        var outcome = await enforcer.ApplyScopedBlockAsync(
            AuthorizedIntent(@"C:\Agents\opencode.exe", "198.51.100.10"),
            "req-apply-1",
            Observed,
            CancellationToken.None);

        Assert.True(outcome.Applied);
        Assert.True(outcome.ReadbackVerified);
        Assert.NotNull(outcome.ManagedRuleId);
        Assert.NotEqual(EnforcementReceiptResult.OsDenyVerified, outcome.Receipt.Result);
        Assert.Equal(EnforcementReceiptResult.DenyRequested, outcome.Receipt.Result);
        Assert.Equal(0, journal.Summarize().OsDenyVerified);
    }

    [Fact]
    public async Task Dual_destination_canary_awards_os_deny_verified_only_when_blocked_fails_and_control_succeeds()
    {
        var blockedEndpoint = new IPEndPoint(IPAddress.Parse("198.51.100.10"), 443);
        var controlEndpoint = new IPEndPoint(IPAddress.Parse("203.0.113.20"), 443);

        var journal = new EnforcementReceiptJournal();
        var probe = new FakeCanaryProbe();
        probe.SetResult(blockedEndpoint, false);
        probe.SetResult(controlEndpoint, true);

        var enforcer = new AgentFirewallEnforcer(_coordinator, journal, probe);
        var apply = await enforcer.ApplyScopedBlockAsync(
            AuthorizedIntent(@"C:\Agents\codex.exe", "198.51.100.10"),
            "req-canary-apply",
            Observed,
            CancellationToken.None);

        var canary = await enforcer.VerifyDualDestinationCanaryAsync(
            apply.ManagedRuleId!.Value,
            @"C:\Agents\codex.exe",
            blockedEndpoint,
            controlEndpoint,
            "rev-1",
            "req-canary-probe",
            Observed,
            CancellationToken.None);

        Assert.True(canary.Verified);
        Assert.True(canary.Observation.BlockedEndpointDenied);
        Assert.True(canary.Observation.PermittedControlEndpointSucceeded);
        Assert.True(canary.Observation.OsRuleReadbackVerified);
        Assert.Equal(EnforcementReceiptResult.OsDenyVerified, canary.Receipt.Result);
        Assert.Equal(EnforcementObservedSideEffect.Absent, canary.Receipt.ObservedSideEffect);
        Assert.Equal("dual-dest-network-canary", canary.Receipt.VerifiedBy);

        var rollback = await enforcer.RollbackTrackedRulesAsync(Actor, CancellationToken.None);
        Assert.Equal(1, rollback.RemovedCount);
        Assert.Equal(0, rollback.OrphanedCount);
        Assert.Empty(enforcer.TrackedRuleIds);
    }

    [Fact]
    public async Task Overbroad_block_or_bypassed_block_never_emits_os_deny_verified()
    {
        var blockedEndpoint = new IPEndPoint(IPAddress.Parse("198.51.100.10"), 443);
        var controlEndpoint = new IPEndPoint(IPAddress.Parse("203.0.113.20"), 443);

        var journal = new EnforcementReceiptJournal();
        var probe = new FakeCanaryProbe();
        probe.SetResult(blockedEndpoint, false);
        probe.SetResult(controlEndpoint, false); // Control destination also failed -> overbroad block!

        var enforcer = new AgentFirewallEnforcer(_coordinator, journal, probe);
        var apply = await enforcer.ApplyScopedBlockAsync(
            AuthorizedIntent(@"C:\Agents\claude.exe", "198.51.100.10"),
            "req-overbroad",
            Observed,
            CancellationToken.None);

        var overbroadCanary = await enforcer.VerifyDualDestinationCanaryAsync(
            apply.ManagedRuleId!.Value,
            @"C:\Agents\claude.exe",
            blockedEndpoint,
            controlEndpoint,
            "rev-1",
            "req-overbroad-check",
            Observed,
            CancellationToken.None);

        Assert.False(overbroadCanary.Verified);
        Assert.Equal(EnforcementReceiptResult.Unverified, overbroadCanary.Receipt.Result);
        Assert.Equal(0, journal.Summarize().OsDenyVerified);
    }

    private static AgentFirewallRuleIntent AuthorizedIntent(string exe, string remote) => new()
    {
        ExecutablePath = exe,
        RemoteAddressOrCidr = remote,
        RemotePorts = "443",
        Origin = AgentNetworkPolicyOrigin.LocalUserPolicy,
        ExplicitlyAuthorizedByUser = true,
        ActorSid = Actor,
        PolicyRevision = "rev-1",
    };

    private sealed class FakeCanaryProbe : IAgentNetworkCanaryProbe
    {
        private readonly Dictionary<IPEndPoint, bool> _results = [];

        public void SetResult(IPEndPoint endpoint, bool connected) => _results[endpoint] = connected;

        public Task<bool> TryConnectAsync(IPEndPoint endpoint, CancellationToken cancellationToken) =>
            Task.FromResult(_results.TryGetValue(endpoint, out var ok) && ok);
    }
}
