// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Core.Firewall;
using Axiom.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class NetworkRecoveryControllerTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 11, 20, 0, 0, TimeSpan.Zero);

    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "axiom-network-recovery-tests",
        Guid.NewGuid().ToString("N"));

    private readonly string _path;

    private readonly FakeDns _dns = new();

    private readonly FakeRuleRecovery _firewall = new();

    private bool _writeAuthorized = true;

    private bool _protectionActive = true;

    public NetworkRecoveryControllerTests()
    {
        _path = Path.Combine(_directory, NetworkRecoverySnapshotStore.FileName);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public async Task Capture_persists_once_and_keeps_the_existing_baseline()
    {
        _dns.Adapters.Add(Adapter("Ethernet", staticV4: ["192.168.0.1"]));
        var controller = Create();
        var first = await controller.CaptureAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.Succeeded, first.Status);
        Assert.True(first.Persisted);
        Assert.True(first.ProtectionWasActive);
        var text = File.ReadAllText(_path);

        _dns.Adapters.Clear();
        _dns.Adapters.Add(Adapter("Wi-Fi", staticV4: ["9.9.9.9"]));
        var second = await controller.CaptureAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.AlreadyCaptured, second.Status);
        Assert.Equal(1, second.AdapterCount);
        Assert.Equal(text, File.ReadAllText(_path));
    }

    [Fact]
    public async Task Capture_keeps_owned_rules_and_ignores_foreign_metadata()
    {
        var owned = Rule("11111111-1111-1111-1111-111111111111", FirewallDirection.Outbound, "Axiom");
        var foreign = Rule("22222222-2222-2222-2222-222222222222", FirewallDirection.Inbound, "OtherProduct");
        _firewall.Rules.AddRange([owned, foreign]);

        var result = await Create().CaptureAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.Succeeded, result.Status);
        Assert.Equal(1, result.RuleCount);
        var read = NetworkRecoverySnapshotStore.Read(_path);
        Assert.Equal(NetworkRecoverySnapshotReadStatus.Valid, read.Status);
        var rule = Assert.Single(read.Snapshot!.Rules);
        Assert.Equal(owned.ManagedRuleId, rule.ManagedRuleId);
        Assert.Equal(FirewallDirection.Outbound, rule.Direction);
    }

    [Fact]
    public async Task Capture_does_not_add_a_rule_when_the_os_metadata_no_longer_proves_ownership()
    {
        var rule = Rule("11111111-1111-1111-1111-111111111111", FirewallDirection.Outbound, "Axiom")
            with { OwnershipGroup = "SomeoneElse", OwnershipDescription = "unrelated rule" };
        _firewall.Rules.Add(rule);

        var result = await Create().CaptureAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.Succeeded, result.Status);
        Assert.Equal(0, result.RuleCount);
    }

    [Fact]
    public async Task Capture_refuses_to_replace_a_corrupt_snapshot()
    {
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(_path, "garbage");
        _dns.Adapters.Add(Adapter("Ethernet", staticV4: ["192.168.0.1"]));

        var result = await Create().CaptureAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.SnapshotCorrupt, result.Status);
        Assert.Equal("garbage", await File.ReadAllTextAsync(_path));
        Assert.Empty(_dns.Applied);
    }

    [Fact]
    public async Task Capture_refuses_a_baseline_that_only_points_at_the_loopback_resolver()
    {
        _dns.Adapters.Add(Adapter("Ethernet", staticV4: ["127.0.0.1"]));

        var result = await Create(loopbackExpected: true).CaptureAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.Failed, result.Status);
        Assert.Contains(result.Problems, problem => problem.Code == "snapshot.loopback_state");
        Assert.False(File.Exists(_path));
    }

    [Fact]
    public async Task Capture_still_saves_a_non_loopback_baseline_when_the_resolver_is_expected()
    {
        _dns.Adapters.Add(Adapter("Ethernet", staticV4: ["192.168.0.1"]));

        var result = await Create(loopbackExpected: true).CaptureAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.Succeeded, result.Status);
        Assert.True(File.Exists(_path));
    }

    [Fact]
    public async Task Capture_does_not_persist_when_firewall_capture_fails()
    {
        _firewall.FailList = true;

        var result = await Create().CaptureAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.Failed, result.Status);
        Assert.False(File.Exists(_path));
    }

    [Fact]
    public async Task Capture_reports_a_write_failure_instead_of_claiming_a_baseline()
    {
        _dns.Adapters.Add(Adapter("Ethernet", staticV4: ["192.168.0.1"]));
        Directory.CreateDirectory(_directory);

        var result = await Create(_directory).CaptureAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.Failed, result.Status);
        Assert.False(result.Persisted);
        Assert.Contains(result.Problems, problem => problem.Code == "snapshot.write_failed");
    }

    [Fact]
    public async Task Valid_empty_snapshot_restores_as_success_unlike_a_missing_file()
    {
        var controller = Create();
        var captured = await controller.CaptureAsync(Actor, CancellationToken.None);
        Assert.Equal(NetworkRecoveryStatus.Succeeded, captured.Status);
        Assert.Equal(0, captured.AdapterCount);
        Assert.Equal(0, captured.RuleCount);

        var restored = await controller.RestoreAsync(Actor, CancellationToken.None);
        Assert.Equal(NetworkRecoveryStatus.Succeeded, restored.Status);
        Assert.True(restored.Verified);

        var missing = await Create(Path.Combine(_directory, "missing.txt"))
            .RestoreAsync(Actor, CancellationToken.None);
        Assert.Equal(NetworkRecoveryStatus.NoSnapshot, missing.Status);
        Assert.False(missing.Verified);
    }

    [Fact]
    public async Task Restore_rejects_an_unauthorized_caller_without_touching_the_machine()
    {
        _dns.Adapters.Add(Adapter("Ethernet", staticV4: ["192.168.0.1"]));
        var controller = Create();
        await controller.CaptureAsync(Actor, CancellationToken.None);
        _dns.Applied.Clear();
        _writeAuthorized = false;

        var result = await controller.RestoreAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.NotAuthorized, result.Status);
        Assert.Empty(_dns.Applied);
        Assert.Empty(_firewall.Removed);
    }

    [Fact]
    public async Task Restore_applies_static_and_automatic_dns_per_family_and_verifies()
    {
        _dns.Adapters.Add(new NetworkAdapterDnsState
        {
            AdapterId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
            InterfaceAlias = "Ethernet",
            Description = "Wired",
            Ipv4Mode = NetworkDnsMode.Static,
            Ipv4Servers = ["192.168.0.1", "1.1.1.1"],
            Ipv6Mode = NetworkDnsMode.Automatic,
        });
        _dns.Adapters.Add(new NetworkAdapterDnsState
        {
            AdapterId = Guid.Parse("22222222-2222-2222-2222-222222222222"),
            InterfaceAlias = "Wi-Fi",
            Description = "Wireless",
            Ipv4Mode = NetworkDnsMode.Automatic,
            Ipv6Mode = NetworkDnsMode.Static,
            Ipv6Servers = ["2606:4700:4700::1111"],
        });

        var controller = Create();
        await controller.CaptureAsync(Actor, CancellationToken.None);

        // Simulate Axiom's change: both adapters now point at the loopback resolver.
        _dns.Adapters[0] = _dns.Adapters[0] with
        {
            Ipv4Mode = NetworkDnsMode.Static,
            Ipv4Servers = ["127.0.0.1"],
        };
        _dns.Adapters[1] = _dns.Adapters[1] with
        {
            Ipv6Mode = NetworkDnsMode.Static,
            Ipv6Servers = ["::1"],
        };

        var result = await controller.RestoreAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.Succeeded, result.Status);
        Assert.True(result.Verified);
        Assert.Equal(2, result.AdaptersRestored);
        Assert.Equal(2, result.AdaptersVerified);
        Assert.Equal(NetworkDnsMode.Automatic, _dns.Adapters[0].Ipv6Mode);
        Assert.Equal(["192.168.0.1", "1.1.1.1"], _dns.Adapters[0].Ipv4Servers);
        Assert.Equal(NetworkDnsMode.Automatic, _dns.Adapters[1].Ipv4Mode);
        Assert.Equal(["2606:4700:4700::1111"], _dns.Adapters[1].Ipv6Servers);
    }

    [Fact]
    public async Task Restore_never_removes_a_rule_whose_ownership_metadata_changed()
    {
        var id = Guid.Parse("11111111-1111-1111-1111-111111111111");
        _firewall.Rules.Add(Rule(id.ToString("D"), FirewallDirection.Outbound, "Axiom"));
        var controller = Create();
        await controller.CaptureAsync(Actor, CancellationToken.None);

        _firewall.Presence[id] = OwnedRulePresence.ForeignOrChanged;
        var result = await controller.RestoreAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.Failed, result.Status);
        Assert.Equal(0, result.RulesRemoved);
        Assert.Empty(_firewall.Removed);
        Assert.Contains(result.Problems, problem => problem.Code == "rule.not_owned");
    }

    [Fact]
    public async Task Restore_removes_only_the_captured_direction()
    {
        var outbound = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var inbound = Guid.Parse("22222222-2222-2222-2222-222222222222");
        _firewall.Rules.Add(Rule(outbound.ToString("D"), FirewallDirection.Outbound, "Axiom"));
        var controller = Create();
        await controller.CaptureAsync(Actor, CancellationToken.None);

        // Rules and directions applied after the capture are outside the validated state.
        _firewall.Rules.Add(Rule(inbound.ToString("D"), FirewallDirection.Inbound, "Axiom"));
        var later = Guid.Parse("33333333-3333-3333-3333-333333333333");
        _firewall.Rules.Add(Rule(later.ToString("D"), FirewallDirection.Outbound, "Axiom"));

        var result = await controller.RestoreAsync(Actor, CancellationToken.None);

        Assert.True(result.Succeeded());
        var removed = Assert.Single(_firewall.Removed);
        Assert.Equal(outbound, removed.Id);
        Assert.Equal(FirewallDirection.Outbound, removed.Direction);
        Assert.Contains(_firewall.Rules, rule => rule.ManagedRuleId == inbound);
        Assert.Contains(_firewall.Rules, rule => rule.ManagedRuleId == later);
    }

    [Fact]
    public async Task Dns_only_restore_never_removes_a_firewall_rule()
    {
        _dns.Adapters.Add(Adapter("Ethernet", staticV4: ["192.168.0.1"]));
        var id = Guid.Parse("11111111-1111-1111-1111-111111111111");
        _firewall.Rules.Add(Rule(id.ToString("D"), FirewallDirection.Outbound, "Axiom"));
        var controller = Create();
        await controller.CaptureAsync(Actor, CancellationToken.None);

        _dns.Adapters[0] = _dns.Adapters[0] with
        {
            Ipv4Mode = NetworkDnsMode.Static,
            Ipv4Servers = ["127.0.0.1"],
        };

        var result = await controller.RestoreDnsOnlyAsync("service-watchdog", CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.Succeeded, result.Status);
        Assert.True(result.Verified);
        Assert.Empty(_firewall.Removed);
        Assert.Single(_firewall.Rules);
        Assert.Equal(["192.168.0.1"], _dns.Adapters[0].Ipv4Servers);
    }

    [Fact]
    public async Task Repeated_restore_is_idempotent_and_reports_verified_absence()
    {
        var id = Guid.Parse("11111111-1111-1111-1111-111111111111");
        _dns.Adapters.Add(Adapter("Ethernet", staticV4: ["192.168.0.1"]));
        _firewall.Rules.Add(Rule(id.ToString("D"), FirewallDirection.Outbound, "Axiom"));
        var controller = Create();
        await controller.CaptureAsync(Actor, CancellationToken.None);

        var first = await controller.RestoreAsync(Actor, CancellationToken.None);
        var second = await controller.RestoreAsync(Actor, CancellationToken.None);

        Assert.True(first.Verified);
        Assert.Equal(1, first.RulesRemoved);
        Assert.True(second.Verified);
        Assert.Equal(0, second.RulesRemoved);
        Assert.Equal(1, second.RulesVerifiedAbsent);
    }

    [Fact]
    public async Task Restore_continues_after_one_adapter_fails_and_reports_partial_success()
    {
        _dns.Adapters.Add(Adapter("Ethernet", staticV4: ["192.168.0.1"]));
        _dns.Adapters.Add(Adapter("Wi-Fi", staticV4: ["192.168.0.2"]));
        var controller = Create();
        await controller.CaptureAsync(Actor, CancellationToken.None);
        _dns.FailAlias = "Ethernet";

        var result = await controller.RestoreAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.PartialFailure, result.Status);
        Assert.Equal(1, result.AdaptersRestored);
        Assert.Contains(result.Problems, problem => problem.Item == "Ethernet");
        Assert.Contains("Wi-Fi", _dns.Applied);
    }

    [Fact]
    public async Task An_interrupted_restore_leaves_the_snapshot_for_a_safe_retry()
    {
        _dns.Adapters.Add(Adapter("Ethernet", staticV4: ["192.168.0.1"]));
        var id = Guid.Parse("11111111-1111-1111-1111-111111111111");
        _firewall.Rules.Add(Rule(id.ToString("D"), FirewallDirection.Outbound, "Axiom"));
        var controller = Create();
        await controller.CaptureAsync(Actor, CancellationToken.None);

        _dns.FailAlias = "Ethernet";
        var interrupted = await controller.RestoreAsync(Actor, CancellationToken.None);
        Assert.False(interrupted.Verified);
        Assert.Equal(NetworkRecoverySnapshotReadStatus.Valid, NetworkRecoverySnapshotStore.Read(_path).Status);

        _dns.FailAlias = null;
        var retried = await controller.RestoreAsync(Actor, CancellationToken.None);

        Assert.True(retried.Verified);
        Assert.Equal(1, retried.RulesVerifiedAbsent);
    }

    [Fact]
    public async Task Concurrent_restore_calls_are_serialised()
    {
        _dns.Adapters.Add(Adapter("Ethernet", staticV4: ["192.168.0.1"]));
        var controller = Create();
        await controller.CaptureAsync(Actor, CancellationToken.None);
        _dns.ApplyDelay = TimeSpan.FromMilliseconds(100);

        var first = controller.RestoreAsync(Actor, CancellationToken.None);
        var second = controller.RestoreAsync(Actor, CancellationToken.None);
        var results = await Task.WhenAll(first, second);

        Assert.All(results, result => Assert.True(result.Verified));
        Assert.False(_dns.Overlapped);
    }

    [Fact]
    public async Task A_restarted_controller_reads_the_same_snapshot()
    {
        _dns.Adapters.Add(Adapter("Ethernet", staticV4: ["192.168.0.1"]));
        var id = Guid.Parse("11111111-1111-1111-1111-111111111111");
        _firewall.Rules.Add(Rule(id.ToString("D"), FirewallDirection.Outbound, "Axiom"));
        await Create().CaptureAsync(Actor, CancellationToken.None);

        var restarted = new NetworkRecoveryController(
            _dns,
            _firewall,
            () => true,
            () => true,
            _path,
            logger: NullLogger<NetworkRecoveryController>.Instance,
            clock: () => Now);

        var result = await restarted.RestoreAsync(Actor, CancellationToken.None);

        Assert.True(result.Verified);
        Assert.Equal(1, result.RulesRemoved);
    }

    [Fact]
    public async Task Corrupt_snapshot_is_refused_without_changing_anything()
    {
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(_path, "axiom-network-recovery=2\nbroken");
        _dns.Adapters.Add(Adapter("Ethernet", staticV4: ["192.168.0.1"]));

        var result = await Create().RestoreAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.SnapshotCorrupt, result.Status);
        Assert.Empty(_dns.Applied);
        Assert.Empty(_firewall.Removed);
    }

    [Fact]
    public async Task Restore_fails_verification_when_dns_server_order_is_reversed()
    {
        _dns.Adapters.Add(Adapter("Ethernet", staticV4: ["1.1.1.1", "8.8.8.8"]));
        var controller = Create();
        await controller.CaptureAsync(Actor, CancellationToken.None);

        _dns.ReverseAppliedServers = true;
        var result = await controller.RestoreAsync(Actor, CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.PartialFailure, result.Status);
        Assert.False(result.Verified);
        Assert.Contains(result.Problems, problem => problem.Code == "dns.verify_failed");
    }

    private NetworkRecoveryController Create(string? path = null, bool loopbackExpected = false) => new(
        _dns,
        _firewall,
        () => _writeAuthorized,
        () => _protectionActive,
        path ?? _path,
        logger: NullLogger<NetworkRecoveryController>.Instance,
        clock: () => Now,
        isLoopbackResolverExpected: loopbackExpected ? () => true : null);

    private static NetworkAdapterDnsState Adapter(string alias, params string[] staticV4) => new()
    {
        AdapterId = Guid.NewGuid(),
        InterfaceAlias = alias,
        Description = alias + " adapter",
        Ipv4Mode = staticV4.Length == 0 ? NetworkDnsMode.Automatic : NetworkDnsMode.Static,
        Ipv4Servers = staticV4,
        Ipv6Mode = NetworkDnsMode.Automatic,
    };

    private static ManagedRule Rule(string id, FirewallDirection direction, string group)
    {
        var managedRuleId = Guid.Parse(id);
        return new ManagedRule
        {
            ManagedRuleId = managedRuleId,
            OsRuleName = OwnedRuleName.Create(managedRuleId, direction),
            State = RuleState.Applied,
            Spec = new RuleSpec
            {
                ManagedRuleId = managedRuleId,
                AppPath = @"C:\test.exe",
                Direction = direction,
                Action = FirewallAction.Block,
                Profiles = FirewallProfile.All,
                CreatedBy = "test",
            },
            OwnershipGroup = group,
            OwnershipDescription = group + " managed rule",
        };
    }

    private sealed class FakeDns : INetworkRecoveryDnsAdapter
    {
        private int _active;

        public List<NetworkAdapterDnsState> Adapters { get; } = [];

        public List<string> Applied { get; } = [];

        public string? FailAlias { get; set; }

        public bool ReverseAppliedServers { get; set; }

        public TimeSpan ApplyDelay { get; set; }

        public bool Overlapped { get; private set; }

        public IReadOnlyList<NetworkAdapterDnsState> CaptureDns() =>
            Adapters.ToList();

        public void ApplyDns(NetworkAdapterDnsState state)
        {
            if (Interlocked.Increment(ref _active) > 1)
            {
                Overlapped = true;
            }

            try
            {
                if (ApplyDelay > TimeSpan.Zero)
                {
                    Thread.Sleep(ApplyDelay);
                }

                if (string.Equals(state.InterfaceAlias, FailAlias, StringComparison.Ordinal))
                {
                    throw new NetworkRecoveryPlatformException("dns.test_failure", "The test adapter refused the change.");
                }

                var appliedState = ReverseAppliedServers
                    ? state with { Ipv4Servers = state.Ipv4Servers.Reverse().ToArray() }
                    : state;
                var index = Adapters.FindIndex(adapter => adapter.AdapterId == state.AdapterId);
                if (index >= 0)
                {
                    Adapters[index] = appliedState;
                }
                else
                {
                    Adapters.Add(appliedState);
                }

                Applied.Add(state.InterfaceAlias);
            }
            finally
            {
                Interlocked.Decrement(ref _active);
            }
        }

        public void FlushDnsCache()
        {
        }

        public bool AnyAdapterUsesLoopbackDns() => false;
    }

    private sealed class FakeRuleRecovery : IOwnedRuleRecoveryAdapter
    {
        public List<ManagedRule> Rules { get; } = [];

        public Dictionary<Guid, OwnedRulePresence> Presence { get; } = [];

        public List<(Guid Id, FirewallDirection Direction)> Removed { get; } = [];

        public bool FailList { get; set; }

        public Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct) =>
            FailList
                ? throw new InvalidOperationException("The test firewall refused the read.")
                : Task.FromResult<IReadOnlyList<ManagedRule>>(Rules.ToList());

        public Task<OwnedRulePresence> InspectOwnedRuleAsync(
            Guid managedRuleId,
            FirewallDirection direction,
            CancellationToken ct)
        {
            if (Presence.TryGetValue(managedRuleId, out var forced))
            {
                return Task.FromResult(forced);
            }

            var present = Rules.Any(rule =>
                rule.ManagedRuleId == managedRuleId && rule.Spec.Direction == direction);
            return Task.FromResult(present ? OwnedRulePresence.Owned : OwnedRulePresence.Absent);
        }

        public Task<RuleApplyResult> RemoveCapturedOwnedRuleAsync(
            Guid managedRuleId,
            FirewallDirection direction,
            CancellationToken ct)
        {
            var rule = Rules.FirstOrDefault(candidate =>
                candidate.ManagedRuleId == managedRuleId && candidate.Spec.Direction == direction);
            if (rule is null)
            {
                return Task.FromResult(new RuleApplyResult
                {
                    Success = true,
                    ManagedRuleId = managedRuleId,
                    State = RuleState.Desired,
                });
            }

            Rules.Remove(rule);
            Removed.Add((managedRuleId, direction));
            return Task.FromResult(new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = managedRuleId,
                State = RuleState.Desired,
            });
        }
    }

    private const string Actor = "S-1-5-21-test";
}

internal static class NetworkRecoveryResultAssertions
{
    public static bool Succeeded(this NetworkRecoveryRestoreResult result) =>
        result.Status == NetworkRecoveryStatus.Succeeded && result.Verified;
}
