// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Axiom.Infrastructure.Linux.Nft;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

public sealed class NftFirewallPolicyAdapterTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 12, 12, 0, 0, TimeSpan.Zero);

    private sealed class Harness : IDisposable
    {
        public TempDirectory Dir { get; } = new();

        public FakeNftRunner Nft { get; } = new();

        public FakeCgroupFs Fs { get; } = new();

        public CollectingSink Sink { get; } = new();

        public ManualTimeProvider Time { get; } = new(Start);

        public bool GateOpen { get; set; } = true;

        public NftFirewallPolicyAdapter Adapter { get; }

        public NftEnginePaths Paths { get; }

        public Harness()
        {
            Fs.AppPaths["/usr/bin/curl"] = "/usr/bin/curl";
            Fs.Processes[500] = ("/usr/bin/curl", "user.slice/user-1000.slice/session-3.scope");
            Paths = new NftEnginePaths(Path.Combine(Dir.Path, "filter"));
            Adapter = new NftFirewallPolicyAdapter(Paths, new NftTable(Nft), new AppCgroupManager(Fs), Sink, () => GateOpen, Time);
        }

        public void Dispose()
        {
            Adapter.Dispose();
            Dir.Dispose();
        }
    }

    [Fact]
    public async Task Upsert_applies_an_atomic_generation_herds_the_live_process_and_reports_it()
    {
        using var h = new Harness();
        var spec = Specs.Block("/usr/bin/curl", Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"));

        var result = await h.Adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(RuleState.Applied, result.State);
        Assert.Equal(OwnedRuleName.Create(spec.ManagedRuleId, FirewallDirection.Outbound), result.OsRuleName);
        Assert.Equal(1, h.Nft.TableGeneration);
        Assert.Contains("socket cgroupv2 level 2 \"axiom.slice/a-", h.Nft.AppliedScript, StringComparison.Ordinal);
        Assert.Equal(h.Nft.AppliedScript, await File.ReadAllTextAsync(h.Paths.RulesFile));
        Assert.StartsWith("axiom.slice/a-", h.Fs.Processes[500].Cgroup, StringComparison.Ordinal);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(h.Paths.ManagedRulesFile));
        }

        var enforcement = h.Adapter.Enforcement;
        Assert.NotNull(enforcement);
        Assert.Equal(1, enforcement.Generation);
        Assert.Equal(1, enforcement.AppliedRuleCount);
        Assert.Empty(enforcement.RejectedRules);
        Assert.Null(enforcement.FileError);
        Assert.Equal(2, h.Sink.Lines.Count);
        Assert.Contains("\"type\":\"filter.hello\"", h.Sink.Lines[0], StringComparison.Ordinal);
        Assert.Contains("\"type\":\"filter.rules\"", h.Sink.Lines[1], StringComparison.Ordinal);

        var owned = Assert.Single(await h.Adapter.ListOwnedRulesAsync(CancellationToken.None));
        Assert.Equal(OwnedRuleOwnership.GroupName, owned.OwnershipGroup);
        Assert.Equal(OwnedRulePresence.Owned, await h.Adapter.InspectOwnedRuleAsync(spec.ManagedRuleId, FirewallDirection.Outbound, CancellationToken.None));
        Assert.Equal(OwnedRulePresence.ForeignOrChanged, await h.Adapter.InspectOwnedRuleAsync(spec.ManagedRuleId, FirewallDirection.Inbound, CancellationToken.None));

        var capabilities = await h.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FirewallCapabilityStatus.Available, capabilities.Status);
        Assert.True(capabilities.FirewallServiceRunning);
        Assert.Equal(1, capabilities.ManagedRuleCount);
        Assert.Same(enforcement, capabilities.FilterEnforcement);
    }

    [Fact]
    public async Task Rejected_rules_are_stored_reported_and_never_widened()
    {
        using var h = new Harness();
        var bad = Specs.Block("/usr/bin/curl", Guid.Parse("7c9e6679-7425-40de-944b-e07fc1f90ae7")) with { RemoteAddresses = ["1.2.3"] };
        var missing = Specs.Block("/opt/not-installed/app", Guid.Parse("11111111-1111-1111-1111-111111111111"));
        var good = Specs.Block("/usr/bin/curl", Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"));

        var badResult = await h.Adapter.UpsertOwnedRuleAsync(bad, CancellationToken.None);
        await h.Adapter.UpsertOwnedRuleAsync(missing, CancellationToken.None);
        await h.Adapter.UpsertOwnedRuleAsync(good, CancellationToken.None);

        Assert.True(badResult.Success);
        Assert.Equal(RuleState.Pending, badResult.State);
        Assert.Equal("nft.rule_rejected", badResult.ErrorCode);
        Assert.Contains("invalid address '1.2.3'", badResult.ErrorMessage, StringComparison.Ordinal);
        Assert.Equal(3, (await h.Adapter.ListOwnedRulesAsync(CancellationToken.None)).Count);
        var enforcement = h.Adapter.Enforcement!;
        Assert.Equal(3, enforcement.Generation);
        Assert.Equal(1, enforcement.AppliedRuleCount);
        Assert.Equal(2, enforcement.RejectedRules.Count);
        Assert.Contains(enforcement.RejectedRules, r => r.RuleId == "7c9e6679-7425-40de-944b-e07fc1f90ae7" && r.Reason.Contains("invalid address", StringComparison.Ordinal));
        Assert.Contains(enforcement.RejectedRules, r => r.RuleId == "11111111-1111-1111-1111-111111111111" && r.Reason.Contains("not reachable", StringComparison.Ordinal));
        Assert.DoesNotContain("axiom:7c9e6679", h.Nft.AppliedScript, StringComparison.Ordinal);
        Assert.Contains("axiom:0f8fad5b", h.Nft.AppliedScript, StringComparison.Ordinal);

        var verify = await h.Adapter.VerifyAsync(bad, CancellationToken.None);
        Assert.False(verify.PresentInOs);
        Assert.True(verify.MatchesSpec);
        Assert.Null(verify.EffectiveAction);
        Assert.Contains("invalid address", verify.FilterRejectionReason, StringComparison.Ordinal);

        using var rules = JsonDocument.Parse(h.Sink.Lines[^1]);
        Assert.Equal(2, rules.RootElement.GetProperty("rejected").GetArrayLength());
    }

    [Fact]
    public async Task Verify_reads_counters_from_the_table_and_remove_republishes_without_the_rule()
    {
        using var h = new Harness();
        var spec = Specs.Block("/usr/bin/curl", Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"));
        await h.Adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);
        h.Nft.ListJson = """
            {"nftables":[{"table":{"family":"inet","name":"axiom","handle":1,"comment":"axiom generation 1"}},
            {"rule":{"family":"inet","table":"axiom","chain":"axiom_out","handle":5,"comment":"axiom:0f8fad5b-d9cb-469f-a165-70867728950e:1","expr":[{"counter":{"packets":2,"bytes":120}},{"reject":{"type":"tcp reset"}}]}}]}
            """;

        var verify = await h.Adapter.VerifyAsync(spec, CancellationToken.None);

        Assert.True(verify.PresentInOs);
        Assert.True(verify.MatchesSpec);
        Assert.Equal(FirewallAction.Block, verify.EffectiveAction);
        Assert.Null(verify.FilterRejectionReason);
        Assert.Contains(verify.Notes, note => note.Contains("1 nft rule(s), 2 packet(s) matched", StringComparison.Ordinal));

        h.Nft.ListJson = null;
        var removed = await h.Adapter.RemoveOwnedRuleAsync(spec.ManagedRuleId, CancellationToken.None);
        Assert.True(removed.Success);
        Assert.Equal(RuleState.Desired, removed.State);
        Assert.Equal(2, h.Nft.TableGeneration);
        Assert.DoesNotContain("axiom:0f8fad5b", h.Nft.AppliedScript, StringComparison.Ordinal);
        Assert.Empty(await h.Adapter.ListOwnedRulesAsync(CancellationToken.None));
        Assert.Equal(0, h.Adapter.Enforcement!.AppliedRuleCount);

        var gone = await h.Adapter.VerifyAsync(spec, CancellationToken.None);
        Assert.False(gone.PresentInOs);
        Assert.False(gone.MatchesSpec);
        Assert.Contains(gone.Notes, note => note.Contains("not in managed-rules.json", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Nft_failure_keeps_the_previous_generation_and_degrades_capabilities()
    {
        using var h = new Harness();
        var first = Specs.Block("/usr/bin/curl", Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"));
        await h.Adapter.UpsertOwnedRuleAsync(first, CancellationToken.None);
        h.Nft.ApplyError = "Error: Could not process rule: Operation not supported";

        var result = await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl"), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("nft.apply_failed", result.ErrorCode);
        Assert.Contains("Operation not supported", result.ErrorMessage, StringComparison.Ordinal);
        var enforcement = h.Adapter.Enforcement!;
        Assert.Equal(1, enforcement.Generation);
        Assert.Equal(1, enforcement.AppliedRuleCount);
        Assert.Contains("Operation not supported", enforcement.FileError, StringComparison.Ordinal);
        var capabilities = await h.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FirewallCapabilityStatus.Degraded, capabilities.Status);
        Assert.Contains("previous generation stays in force", capabilities.Reason, StringComparison.Ordinal);
        Assert.Equal(2, capabilities.ManagedRuleCount); // ownership is persisted first, so a restart republishes both

        h.Nft.ApplyError = null;
        Assert.Equal(3, await h.Adapter.PublishAsync(CancellationToken.None));
        Assert.Equal(2, h.Adapter.Enforcement!.AppliedRuleCount);
    }

    [Fact]
    public async Task Foreign_flush_is_reported_and_teardown_removes_table_and_cgroups()
    {
        using var h = new Harness();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl"), CancellationToken.None);
        h.Nft.TableGeneration = null; // somebody ran `nft flush ruleset`

        var capabilities = await h.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FirewallCapabilityStatus.Degraded, capabilities.Status);
        Assert.Contains("table inet axiom is missing", capabilities.Reason, StringComparison.Ordinal);
        Assert.False(capabilities.FirewallServiceRunning);

        h.Fs.Processes.Clear();
        await h.Adapter.TeardownAsync(CancellationToken.None);
        Assert.Contains(h.Nft.Calls, call => string.Join(' ', call.Args) == "delete table inet axiom");
        Assert.DoesNotContain(h.Fs.Cgroups, c => c.StartsWith("axiom.slice", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Unmovable_live_process_marks_the_rule_rejected()
    {
        using var h = new Harness();
        h.Fs.Unmovable.Add(500);
        var spec = Specs.Block("/usr/bin/curl", Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"));

        var result = await h.Adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("nft.rule_rejected", result.ErrorCode);
        Assert.Contains("live process pid 500 (/usr/bin/curl) could not be moved", result.ErrorMessage, StringComparison.Ordinal);
        Assert.Equal(0, h.Adapter.Enforcement!.AppliedRuleCount);
        Assert.Single(h.Adapter.Enforcement.RejectedRules);
    }

    [Fact]
    public async Task Writes_need_the_gate_and_recovery_needs_root_or_the_daemon()
    {
        using var h = new Harness { GateOpen = false };
        await Assert.ThrowsAsync<NotSupportedException>(() => h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl"), CancellationToken.None));
        await Assert.ThrowsAsync<NotSupportedException>(() => h.Adapter.RemoveOwnedRuleAsync(Guid.NewGuid(), CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => h.Adapter.RemoveOwnedRuleAsync(Guid.Empty, CancellationToken.None));
        if (!Environment.IsPrivilegedProcess && !ProtectionWriteConsent.IsServiceHost)
        {
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => h.Adapter.RemoveCapturedOwnedRuleAsync(Guid.NewGuid(), FirewallDirection.Outbound, CancellationToken.None));
        }
    }
}
