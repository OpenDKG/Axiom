// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Nft;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

/// <summary>
/// The Linux rule lifecycle after the macOS review (P0 #2/#3, High #4): a rule is Applied only when
/// the batch succeeded, the table read back carries the generation and the rule comment and the
/// app cgroup exists; the enforcement report is verified / pending / degraded / unavailable from
/// the live readback alone.
/// </summary>
public sealed class NftLifecycleTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 12, 12, 0, 0, TimeSpan.Zero);

    private static readonly Guid Id = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");

    private sealed class Harness : IDisposable
    {
        public TempDirectory Dir { get; } = new();

        public FakeNftRunner Nft { get; } = new();

        public FakeCgroupFs Fs { get; } = new();

        public CollectingSink Sink { get; } = new();

        public ManualTimeProvider Time { get; } = new(Start);

        public NftFirewallPolicyAdapter Adapter { get; }

        public Harness()
        {
            Fs.AppPaths["/usr/bin/curl"] = "/usr/bin/curl";
            Adapter = new NftFirewallPolicyAdapter(new NftEnginePaths(Path.Combine(Dir.Path, "filter")), new NftTable(Nft), new AppCgroupManager(Fs), Sink, () => true, Time);
        }

        public void Dispose()
        {
            Adapter.Dispose();
            Dir.Dispose();
        }
    }

    [Theory]
    [InlineData(-1L, null, true, false, FilterEnforcementState.Unavailable)]
    [InlineData(3L, 3L, true, false, FilterEnforcementState.Verified)]
    [InlineData(3L, 2L, true, false, FilterEnforcementState.Pending)]
    [InlineData(3L, null, true, false, FilterEnforcementState.Degraded)]
    [InlineData(3L, 3L, false, false, FilterEnforcementState.Degraded)]
    [InlineData(3L, 3L, true, true, FilterEnforcementState.Degraded)]
    public void Evaluate_is_pure_over_published_live_readability_and_rejection(long published, long? live, bool readable, bool rejected, FilterEnforcementState expected) =>
        Assert.Equal(expected, NftFirewallPolicyAdapter.Evaluate(published, live, readable, rejected));

    [Fact]
    public void Outcome_requires_generation_comment_cgroup_and_herding()
    {
        var spec = Specs.Block("/usr/bin/curl", Id);
        var compiled = new NftCompiledRule(Id, "axiom.slice/a-0123", ["rule"]);
        var compilation = new NftCompilation { Generation = 4, Script = "", Applied = [compiled], Rejected = [] };
        var counters = new List<NftRuleCounter> { new(Id, 1, 7, 0, 0, "axiom_out") };
        var verified = new FilterEnforcementReport { State = FilterEnforcementState.Verified, Connected = true, PublishedGeneration = 4, AckedGeneration = 4, Generation = 4, LastAckUtc = Start, ReportedUtc = Start };

        var applied = NftFirewallPolicyAdapter.Outcome(spec, "name", compilation, 4, counters, verified, cgroupExists: true, []);
        Assert.Equal(RuleState.Applied, applied.State);
        Assert.Equal(Start, applied.VerifiedUtc);

        var wrongGeneration = NftFirewallPolicyAdapter.Outcome(spec, "name", compilation, 3, counters, verified, cgroupExists: true, []);
        Assert.Equal(RuleState.Pending, wrongGeneration.State);
        Assert.Equal("nft.readback_mismatch", wrongGeneration.ErrorCode);
        Assert.Contains("holds generation 3, not 4", wrongGeneration.ErrorMessage, StringComparison.Ordinal);

        var noTable = NftFirewallPolicyAdapter.Outcome(spec, "name", compilation, null, [], verified, cgroupExists: true, []);
        Assert.Equal("nft.readback_mismatch", noTable.ErrorCode);
        Assert.Contains("not present after the apply", noTable.ErrorMessage, StringComparison.Ordinal);

        var noComment = NftFirewallPolicyAdapter.Outcome(spec, "name", compilation, 4, [], verified, cgroupExists: true, []);
        Assert.Equal(RuleState.Pending, noComment.State);
        Assert.Contains("without the rule's comment", noComment.ErrorMessage, StringComparison.Ordinal);

        var noCgroup = NftFirewallPolicyAdapter.Outcome(spec, "name", compilation, 4, counters, verified, cgroupExists: false, []);
        Assert.Equal("nft.cgroup_missing", noCgroup.ErrorCode);

        var herdingFailed = NftFirewallPolicyAdapter.Outcome(spec, "name", compilation, 4, counters, verified, cgroupExists: true,
            [new CgroupPlacement(500, "/usr/bin/curl", "/usr/bin/curl", "user.slice", SourceCgroupKind.UserSessionLeaf, "axiom.slice/a-0123", false, "Permission denied")]);
        Assert.Equal("nft.attribution_failed", herdingFailed.ErrorCode);
        Assert.Equal(RuleState.Pending, herdingFailed.State);

        var refused = NftFirewallPolicyAdapter.Outcome(spec, "name", compilation with { Applied = [], Rejected = [new NftRejectedRule(Id, "hostnames are not supported")] }, 4, [], verified, cgroupExists: false, []);
        Assert.False(refused.Success);
        Assert.Equal(RuleState.Failed, refused.State);
        Assert.Equal("nft.rule_rejected", refused.ErrorCode);
        Assert.Contains("hostnames are not supported", refused.ErrorMessage, StringComparison.Ordinal);

        // A disabled rule has no nft lines: Applied once the generation is verified.
        var disabled = NftFirewallPolicyAdapter.Outcome(spec with { Enabled = false }, "name", compilation with { Applied = [] }, 4, [], verified, cgroupExists: false, []);
        Assert.Equal(RuleState.Applied, disabled.State);
    }

    [Fact]
    public async Task Before_the_first_publish_the_report_is_unavailable_and_rules_are_pending()
    {
        using var h = new Harness();

        var capabilities = await h.Adapter.GetCapabilitiesAsync(CancellationToken.None);

        Assert.Equal(FirewallCapabilityStatus.Available, capabilities.Status);
        Assert.Equal(FilterEnforcementState.Unavailable, capabilities.FilterEnforcement!.State);
        Assert.False(capabilities.FirewallServiceRunning);
        Assert.Contains("not been published yet", capabilities.Reason, StringComparison.Ordinal);
        Assert.Equal(-1, capabilities.FilterEnforcement.PublishedGeneration);
    }

    [Fact]
    public async Task Readback_without_the_rule_comment_keeps_the_rule_pending_until_the_table_is_read_again()
    {
        using var h = new Harness { Nft = { ReadbackWithoutRules = true } };
        var spec = Specs.Block("/usr/bin/curl", Id);

        var result = await h.Adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(RuleState.Pending, result.State);
        Assert.Equal("nft.readback_mismatch", result.ErrorCode);
        Assert.Contains("without the rule's comment", result.ErrorMessage, StringComparison.Ordinal);
        Assert.Equal(FilterEnforcementState.Verified, h.Adapter.Enforcement!.State); // the generation is there, the rule is not
        var verify = await h.Adapter.VerifyAsync(spec, CancellationToken.None);
        Assert.False(verify.PresentInOs);
        Assert.False(verify.EnforcementVerified);
        Assert.Null(verify.EffectiveAction);

        h.Nft.ReadbackWithoutRules = false;
        var again = await h.Adapter.VerifyAsync(spec, CancellationToken.None);
        Assert.True(again.PresentInOs);
        Assert.True(again.EnforcementVerified);
        Assert.Equal(FirewallAction.Block, again.EffectiveAction);
    }

    [Fact]
    public async Task Missing_app_cgroup_keeps_the_rule_pending_and_verify_says_so()
    {
        using var h = new Harness();
        var spec = Specs.Block("/usr/bin/curl", Id);
        await h.Adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);
        var cgroup = Assert.Single(h.Fs.Cgroups, c => c.StartsWith("axiom.slice/a-", StringComparison.Ordinal));
        h.Fs.Cgroups.Remove(cgroup); // another tool rmdir'ed it

        var verify = await h.Adapter.VerifyAsync(spec, CancellationToken.None);

        Assert.True(verify.PresentInOs);
        Assert.False(verify.EnforcementVerified);
        Assert.Null(verify.EffectiveAction);
        Assert.Contains(verify.Notes, note => note.Contains("app cgroup for this rule does not exist", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Table_vanishing_degrades_the_report_and_republishing_verifies_it_again()
    {
        using var h = new Harness();
        var spec = Specs.Block("/usr/bin/curl", Id);
        await h.Adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);
        h.Time.Now = Start.AddMinutes(1);
        h.Nft.TableGeneration = null;

        var lost = await h.Adapter.MarkTableLostAsync(CancellationToken.None);

        Assert.Equal(FilterEnforcementState.Degraded, lost.State);
        Assert.False(lost.Connected);
        Assert.Equal(1, lost.PublishedGeneration);
        Assert.Null(lost.AckedGeneration);
        Assert.Equal(Start, lost.LastSeenUtc);
        Assert.Equal(Start, lost.LastAckUtc);
        Assert.Equal(0, lost.AppliedRuleCount);
        var verify = await h.Adapter.VerifyAsync(spec, CancellationToken.None);
        Assert.False(verify.PresentInOs);
        Assert.False(verify.EnforcementVerified);
        Assert.Contains(verify.Notes, note => note.Contains("not present", StringComparison.Ordinal));

        h.Time.Now = Start.AddMinutes(2);
        Assert.Equal(2, await h.Adapter.PublishAsync(CancellationToken.None));
        var back = await h.Adapter.RefreshAsync(CancellationToken.None);
        Assert.Equal(FilterEnforcementState.Verified, back.State);
        Assert.Equal(2, back.AckedGeneration);
        Assert.Equal(Start.AddMinutes(2), back.LastAckUtc);
        Assert.Equal(1, back.AppliedRuleCount);
        Assert.Equal(RuleState.Applied, Assert.Single(await h.Adapter.ListOwnedRulesAsync(CancellationToken.None)).State);
    }

    [Fact]
    public async Task Unreadable_nft_degrades_capabilities_with_the_error()
    {
        using var h = new Harness();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", Id), CancellationToken.None);
        h.Nft.ListFailure = new System.ComponentModel.Win32Exception(2, "nft: No such file or directory");

        var capabilities = await h.Adapter.GetCapabilitiesAsync(CancellationToken.None);

        Assert.Equal(FirewallCapabilityStatus.Degraded, capabilities.Status);
        Assert.False(capabilities.FirewallServiceRunning);
        Assert.Contains("nftables is unavailable (nft: No such file or directory)", capabilities.Reason, StringComparison.Ordinal);
        Assert.Equal(FilterEnforcementState.Degraded, capabilities.FilterEnforcement!.State);
        Assert.False(capabilities.FilterEnforcement.Connected);
        var verify = await h.Adapter.VerifyAsync(Specs.Block("/usr/bin/curl", Id), CancellationToken.None);
        Assert.Contains(verify.Notes, note => note.Contains("could not be read", StringComparison.Ordinal));
        Assert.False(verify.EnforcementVerified);
    }

    [Fact]
    public async Task Foreign_generation_in_the_table_is_pending_not_verified()
    {
        using var h = new Harness();
        var spec = Specs.Block("/usr/bin/curl", Id);
        await h.Adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);
        h.Nft.TableGeneration = 99; // someone replaced the table with a copy carrying another generation

        var report = await h.Adapter.RefreshAsync(CancellationToken.None);
        var capabilities = await h.Adapter.GetCapabilitiesAsync(CancellationToken.None);

        Assert.Equal(FilterEnforcementState.Pending, report.State);
        Assert.True(report.Connected);
        Assert.Equal(99, report.AckedGeneration);
        Assert.Equal(FirewallCapabilityStatus.Available, capabilities.Status);
        Assert.Contains("holds generation 99; generation 1 is pending", capabilities.Reason, StringComparison.Ordinal);
        var verify = await h.Adapter.VerifyAsync(spec, CancellationToken.None);
        Assert.False(verify.EnforcementVerified);
        Assert.Contains(verify.Notes, note => note.Contains("generation 1 was published; nftables holds 99", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Limitations_name_the_exec_race_and_the_inactive_bpf_layer()
    {
        using var h = new Harness();

        var limitations = (await h.Adapter.GetCapabilitiesAsync(CancellationToken.None)).Limitations;

        Assert.Equal(2, limitations.Count);
        Assert.Contains(limitations, l => l.Contains("within ~1 s of exec", StringComparison.Ordinal));
        Assert.Contains(limitations, l => l.StartsWith("BPF layer inactive", StringComparison.Ordinal));

        h.Adapter.VerdictLayer = new ActiveLayer();
        var closed = (await h.Adapter.GetCapabilitiesAsync(CancellationToken.None)).Limitations;
        Assert.DoesNotContain(closed, l => l.StartsWith("BPF layer inactive", StringComparison.Ordinal));
        Assert.Contains(closed, l => l.Contains("BPF layer closes this window", StringComparison.Ordinal));
    }

    private sealed class ActiveLayer : IVerdictLayer
    {
        public bool Active => true;

        public string Status => "active";

        public Task<LayerSyncResult> SyncAsync(IReadOnlyList<ManagedRule> rules, long generation, CancellationToken ct) =>
            Task.FromResult(new LayerSyncResult { Generation = generation, Attached = true, Pinned = true, Applied = true, Verified = true, Attempts = 1, Status = Status });
    }

    [Fact]
    public async Task Teardown_resets_the_report_to_unavailable()
    {
        using var h = new Harness();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", Id), CancellationToken.None);

        await h.Adapter.TeardownAsync(CancellationToken.None);

        Assert.Null(h.Adapter.Enforcement);
        Assert.Equal(FilterEnforcementState.Unavailable, (await h.Adapter.RefreshAsync(CancellationToken.None)).State);
    }
}
