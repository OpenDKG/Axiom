// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.RegularExpressions;
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Bpf;
using Axiom.Infrastructure.Linux.Nft;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

/// <summary>
/// PR #276 review, LNX-1 + LNX-2 minimum test list (docs/LINUX_TEST_REPORT.md, fault matrix): the
/// real <see cref="BpfEngine"/> over the stateful fake bpftool, the adapter over the fake nft, and the
/// supervisor over both. Third-party objects are pre-seeded and asserted untouched.
/// </summary>
public sealed class LinuxFaultMatrixTests
{
    private static readonly Guid RuleA = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");
    private static readonly Guid RuleB = Guid.Parse("7c9e6679-7425-40de-944b-e07fc1f90ae7");
    private const long ThirdPartyProgram = 7;

    private static BpfEffectiveStateTests.Harness NewHarness()
    {
        var h = new BpfEffectiveStateTests.Harness();
        h.Bpftool.Attached[ThirdPartyProgram] = ("sd_fw_egress", "cgroup_inet_egress");
        return h;
    }

    private static int AxiomAttachments(FakeBpftool bpftool) =>
        bpftool.Attached.Values.Count(program => program.Name.StartsWith("axiom_", StringComparison.Ordinal));

    private static void AssertThirdPartyUntouched(BpfEffectiveStateTests.Harness h)
    {
        Assert.True(h.Bpftool.Attached.TryGetValue(ThirdPartyProgram, out var program), "third-party BPF program still attached");
        Assert.Equal("sd_fw_egress", program.Name);
        Assert.DoesNotContain(h.Bpftool.Calls, call => call.Contains($" id {ThirdPartyProgram}", StringComparison.Ordinal));
        AssertOnlyAxiomTable(h.Nft);
    }

    private static void AssertOnlyAxiomTable(FakeNftRunner nft)
    {
        foreach (var (args, stdin) in nft.Calls)
        {
            var joined = string.Join(' ', args);
            Assert.DoesNotContain("flush ruleset", joined, StringComparison.Ordinal);
            if (joined.Contains("table", StringComparison.Ordinal))
            {
                Assert.Contains("inet axiom", joined, StringComparison.Ordinal);
            }

            if (stdin is not null)
            {
                Assert.DoesNotContain("flush ruleset", stdin, StringComparison.Ordinal);
                foreach (Match match in Regex.Matches(stdin, @"\btable\s+(\w+)\s+(\w+)"))
                {
                    Assert.Equal("inet axiom", match.Groups[1].Value + " " + match.Groups[2].Value);
                }
            }
        }
    }

    [Fact]
    public async Task Persistent_delete_failure_neutralises_only_axiom_programs_and_reattach_restores_a_verified_removal()
    {
        using var h = NewHarness();
        await h.AttachAsync();
        Assert.True((await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None)).Success);
        Assert.Equal(4, AxiomAttachments(h.Bpftool));

        h.Bpftool.FailPrefixes.Add("bpftool map delete");
        var removal = await h.Adapter.RemoveOwnedRuleAsync(RuleA, CancellationToken.None);

        Assert.False(removal.Success);
        Assert.Equal(RuleState.Pending, removal.State);
        Assert.Equal("bpf.delete_failed", removal.ErrorCode);
        Assert.Contains("detached its own BPF programs", removal.ErrorMessage, StringComparison.Ordinal);
        Assert.Null(removal.VerifiedUtc);
        Assert.Equal(3, h.Adapter.LayerSync!.Attempts);
        Assert.True(h.Engine.Neutralised);
        Assert.False(h.Engine.Active);
        Assert.Equal(0, AxiomAttachments(h.Bpftool));
        Assert.Equal(FilterEnforcementState.Degraded, h.Adapter.Enforcement!.State);
        var capabilities = await h.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FirewallCapabilityStatus.Degraded, capabilities.Status);
        Assert.Contains("neutralised", capabilities.Reason, StringComparison.Ordinal);
        AssertThirdPartyUntouched(h);

        // Transient fault over: the watcher's bounded re-attach restores a consistent layer.
        h.Bpftool.FailPrefixes.Clear();
        var supervisor = new NftEnforcementSupervisor(h.Adapter, new NftTable(h.Nft), null, h.Engine, h.Log.Add, h.Time);
        await supervisor.WatchOnceAsync(CancellationToken.None);
        Assert.Equal(1, supervisor.LayerReattachments);
        Assert.True(h.Engine.Active);
        Assert.Equal(4, AxiomAttachments(h.Bpftool));
        Assert.Empty(h.Bpftool.Map(h.BpfPaths.MapPin(BpfLayout.ExeMap)));
        Assert.Empty(h.Bpftool.Map(h.BpfPaths.MapPin(BpfLayout.CgroupMap)));
        Assert.Equal(FilterEnforcementState.Verified, h.Adapter.Enforcement!.State);

        // Retrying the removal (idempotent) now verifies.
        var retry = await h.Adapter.RemoveOwnedRuleAsync(RuleA, CancellationToken.None);
        Assert.True(retry.Success);
        Assert.NotNull(retry.VerifiedUtc);
        AssertThirdPartyUntouched(h);
    }

    [Fact]
    public async Task Delete_and_detach_both_failing_reports_that_the_stale_entry_can_still_block()
    {
        using var h = NewHarness();
        await h.AttachAsync();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        h.Bpftool.FailPrefixes.Add("bpftool map delete");
        h.Bpftool.FailPrefixes.Add("bpftool cgroup detach");

        var removal = await h.Adapter.RemoveOwnedRuleAsync(RuleA, CancellationToken.None);

        Assert.False(removal.Success);
        Assert.Equal(RuleState.Pending, removal.State);
        Assert.Equal("bpf.stale_entry", removal.ErrorCode);
        Assert.Contains("may still be blocked", removal.ErrorMessage, StringComparison.Ordinal);
        Assert.True(h.Adapter.LayerSync!.StaleEntriesCanBlock);
        Assert.StartsWith("degraded:", h.Engine.Status, StringComparison.Ordinal);
        Assert.Equal(FilterEnforcementState.Degraded, h.Adapter.Enforcement!.State);
        var verify = await h.Adapter.VerifyAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        Assert.False(verify.EnforcementVerified);
        Assert.Contains(verify.Notes, note => note.Contains("still in an attached map", StringComparison.Ordinal));
        AssertThirdPartyUntouched(h);
    }

    [Fact]
    public async Task Transient_map_update_failure_is_repaired_by_the_read_back_pass()
    {
        using var h = NewHarness();
        await h.AttachAsync();
        h.Bpftool.FailTimes[$"bpftool map update pinned {h.BpfPaths.MapPin(BpfLayout.CgroupMap)}"] = 1;

        var result = await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);

        Assert.Equal(RuleState.Applied, result.State);
        Assert.True(h.Adapter.LayerSync!.Applied);
        Assert.True(h.Adapter.LayerSync.Verified);
        Assert.Single(h.Bpftool.Map(h.BpfPaths.MapPin(BpfLayout.CgroupMap)));
        Assert.Equal(FilterEnforcementState.Verified, h.Adapter.Enforcement!.State);
    }

    [Fact]
    public async Task Persistent_partial_update_degrades_then_an_idempotent_retry_restores_consistent_enforcement()
    {
        using var h = NewHarness();
        await h.AttachAsync();
        h.Bpftool.FailPrefixes.Add($"bpftool map update pinned {h.BpfPaths.MapPin(BpfLayout.CgroupMap)}");

        var first = await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        Assert.Equal(RuleState.Pending, first.State);
        Assert.Equal("bpf.update_failed", first.ErrorCode);
        Assert.Equal(3, h.Adapter.LayerSync!.Attempts);
        Assert.Single(h.Adapter.LayerSync.FailedUpdates);
        Assert.Equal(FilterEnforcementState.Pending, h.Adapter.Enforcement!.State);

        h.Bpftool.FailPrefixes.Clear();
        var second = await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        Assert.Equal(RuleState.Applied, second.State);
        Assert.Single(h.Bpftool.Map(h.BpfPaths.MapPin(BpfLayout.ExeMap)));
        Assert.Single(h.Bpftool.Map(h.BpfPaths.MapPin(BpfLayout.CgroupMap)));
        Assert.Equal(FilterEnforcementState.Verified, h.Adapter.Enforcement!.State);

        // Same rule again: no duplicate entries, still verified.
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        Assert.Single(h.Bpftool.Map(h.BpfPaths.MapPin(BpfLayout.ExeMap)));
        Assert.Equal(FilterEnforcementState.Verified, h.Adapter.Enforcement!.State);
    }

    [Fact]
    public async Task Unknown_key_left_in_a_pinned_map_is_deleted_by_reconciliation()
    {
        using var h = NewHarness();
        await h.AttachAsync();
        var stale = new string('e', BpfLayout.ExeKeySize * 2);
        h.Bpftool.Maps[h.BpfPaths.MapPin(BpfLayout.ExeMap)][stale] = BpfLayout.HexString(BpfLayout.Verdict(BpfLayout.ActionBlock, BpfLayout.ProtoAny, 0, RuleB));

        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);

        Assert.DoesNotContain(stale, h.Bpftool.Map(h.BpfPaths.MapPin(BpfLayout.ExeMap)).Keys);
        Assert.Single(h.Bpftool.Map(h.BpfPaths.MapPin(BpfLayout.ExeMap)));
        Assert.True(h.Adapter.LayerSync!.Applied);
    }

    [Fact]
    public async Task Permission_denied_on_map_writes_is_reported_not_swallowed()
    {
        using var h = NewHarness();
        await h.AttachAsync();
        h.Bpftool.FailureText = "Error: bpf obj get (/sys/fs/bpf/axiom/maps): Operation not permitted";
        h.Bpftool.FailPrefixes.Add("bpftool map update");

        var result = await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);

        Assert.Equal(RuleState.Pending, result.State);
        Assert.Equal("bpf.update_failed", result.ErrorCode);
        Assert.Contains("Operation not permitted", result.ErrorMessage, StringComparison.Ordinal);
        var capabilities = await h.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Contains(capabilities.Limitations, line => line.StartsWith("BPF map sync failed", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Bpftool_vanishing_at_runtime_is_a_failed_result_not_an_exception()
    {
        using var h = NewHarness();
        await h.AttachAsync();
        h.Bpftool.Missing = true;

        var result = await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);

        Assert.Equal(RuleState.Pending, result.State);
        Assert.Contains("bpftool could not be run", result.ErrorMessage, StringComparison.Ordinal);
        Assert.NotEqual(FilterEnforcementState.Verified, h.Adapter.Enforcement!.State);
    }

    [Fact]
    public async Task Bpftool_unavailable_at_start_leaves_an_honest_nft_only_daemon()
    {
        using var h = NewHarness();
        h.Bpftool.Missing = true;
        var supervisor = new NftEnforcementSupervisor(h.Adapter, new NftTable(h.Nft), null, h.Engine, h.Log.Add, h.Time);

        await supervisor.StartLayerAsync(CancellationToken.None);
        var result = await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);

        Assert.False(h.Engine.Active);
        Assert.Equal(RuleState.Applied, result.State); // nftables enforces it, and says so
        Assert.Equal(FilterEnforcementState.Verified, h.Adapter.Enforcement!.State);
        var verify = await h.Adapter.VerifyAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        Assert.Contains(verify.Notes, note => note.Contains("BPF layer inactive", StringComparison.Ordinal) && note.Contains("nftables alone", StringComparison.Ordinal));
        var capabilities = await h.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Contains(capabilities.Limitations, line => line.StartsWith("BPF layer inactive", StringComparison.Ordinal));
        Assert.DoesNotContain(capabilities.Limitations, line => line.Contains("closes this window", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Missing_map_pin_is_not_mistaken_for_an_already_deleted_key()
    {
        using var h = NewHarness();
        await h.AttachAsync();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        File.Delete(h.BpfPaths.MapPin(BpfLayout.ExeMap));

        var removal = await h.Adapter.RemoveOwnedRuleAsync(RuleA, CancellationToken.None);

        Assert.False(removal.Success && removal.VerifiedUtc is not null);
        Assert.Equal(RuleState.Pending, removal.State);
        Assert.Contains("missing", removal.ErrorMessage, StringComparison.Ordinal);
        AssertThirdPartyUntouched(h);
    }

    [Fact]
    public async Task Programs_detached_by_another_tool_are_reported_and_reattached_by_the_watcher()
    {
        using var h = NewHarness();
        await h.AttachAsync();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        foreach (var id in h.Bpftool.Attached.Where(pair => pair.Value.Name.StartsWith("axiom_", StringComparison.Ordinal)).Select(pair => pair.Key).ToList())
        {
            h.Bpftool.Attached.Remove(id);
        }

        var result = await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);

        Assert.NotEqual(RuleState.Applied, result.State);
        Assert.Equal("bpf.neutralised", result.ErrorCode);
        Assert.Contains("detached by another tool", h.Engine.Status, StringComparison.Ordinal);
        Assert.Equal(FilterEnforcementState.Degraded, h.Adapter.Enforcement!.State);

        var supervisor = new NftEnforcementSupervisor(h.Adapter, new NftTable(h.Nft), null, h.Engine, h.Log.Add, h.Time);
        await supervisor.WatchOnceAsync(CancellationToken.None);
        Assert.Equal(4, AxiomAttachments(h.Bpftool));
        Assert.Equal(2, h.Engine.AppliedEntries.Count);
        Assert.Equal(FilterEnforcementState.Verified, h.Adapter.Enforcement!.State);
        AssertThirdPartyUntouched(h);
    }

    [Fact]
    public async Task Nft_only_scoped_and_inbound_rules_are_distinguished_from_bpf_backed_ones()
    {
        using var h = NewHarness();
        await h.AttachAsync();
        var scoped = Specs.Block("/usr/bin/wget", RuleB) with { RemotePorts = "443" };
        var inbound = Specs.Block("/usr/bin/wget", Guid.Parse("b3c1a2d4-0000-4000-8000-000000000001"), FirewallDirection.Inbound);
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        await h.Adapter.UpsertOwnedRuleAsync(scoped, CancellationToken.None);
        await h.Adapter.UpsertOwnedRuleAsync(inbound, CancellationToken.None);

        var sync = h.Adapter.LayerSync!;
        Assert.Contains(RuleA, sync.CoveredRules);
        Assert.DoesNotContain(RuleB, sync.CoveredRules);
        Assert.DoesNotContain(inbound.ManagedRuleId, sync.CoveredRules);
        Assert.Contains(sync.Uncovered, rule => rule.RuleId == RuleB);

        var curl = await h.Adapter.VerifyAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        Assert.Contains(curl.Notes, note => note.StartsWith("BPF-backed", StringComparison.Ordinal));
        var wget = await h.Adapter.VerifyAsync(scoped, CancellationToken.None);
        Assert.Contains(wget.Notes, note => note.StartsWith("nft-only", StringComparison.Ordinal));
        Assert.DoesNotContain(wget.Notes, note => note.StartsWith("BPF-backed", StringComparison.Ordinal));
        var wgetIn = await h.Adapter.VerifyAsync(inbound, CancellationToken.None);
        Assert.Contains(wgetIn.Notes, note => note.StartsWith("nft-only", StringComparison.Ordinal));
        var capabilities = await h.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Contains(capabilities.Limitations, line => line == NftFirewallPolicyAdapter.BpfCoverageStatement);
    }

    // LNX-2: supervisor lifetime with the real engine.

    private static NftEnforcementSupervisor Supervise(BpfEffectiveStateTests.Harness h, NftFirewallPolicyAdapter adapter, BpfEngine engine) =>
        new(adapter, new NftTable(h.Nft), null, engine, h.Log.Add, h.Time)
        {
            AttributionInterval = TimeSpan.FromMilliseconds(10),
            WatchInterval = TimeSpan.FromMilliseconds(15),
            TeardownStepTimeout = TimeSpan.FromSeconds(2),
        };

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!condition() && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        Assert.True(condition(), "condition not reached within 5 s");
    }

    [Fact]
    public async Task Rapid_stop_start_cycles_leave_no_duplicate_or_orphan_attachments()
    {
        using var h = NewHarness();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        for (var cycle = 0; cycle < 3; cycle++)
        {
            var supervisor = Supervise(h, h.Adapter, h.Engine);
            using var cts = new CancellationTokenSource();
            var run = supervisor.RunAsync(cts.Token);
            await WaitUntilAsync(() => h.Engine.Active && h.Engine.AppliedEntries.Count == 2);
            Assert.Equal(4, AxiomAttachments(h.Bpftool));
            await cts.CancelAsync();
            await run;

            Assert.Equal(0, AxiomAttachments(h.Bpftool));
            Assert.False(Directory.Exists(h.BpfPaths.PinDirectory));
            Assert.Null(h.Nft.TableGeneration);
            Assert.DoesNotContain(h.Fs.Cgroups, cgroup => cgroup.StartsWith("axiom.slice/", StringComparison.Ordinal));
            Assert.Empty(supervisor.TeardownErrors);
        }

        AssertThirdPartyUntouched(h);
    }

    [Fact]
    public async Task Crash_restart_reconciles_orphaned_axiom_state_without_touching_third_party_state()
    {
        using var h = NewHarness();
        h.Fs.Cgroups.Add("system.slice/cron.service");
        h.Fs.Processes[600] = ("/usr/bin/curl", "system.slice/cron.service");
        h.Fs.AppPaths["/usr/bin/gone"] = "/usr/bin/gone";
        await h.AttachAsync();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        h.Adapter.Attribute();

        // A cgroup of a rule that no longer exists, with a herded process, as a crashed daemon leaves it.
        h.Fs.Cgroups.Add("axiom.slice/a-orphan");
        h.Fs.Processes[700] = ("/usr/bin/gone", "axiom.slice/a-orphan");

        // SIGKILL: no teardown. A new daemon instance (fresh engine + adapter over the same state).
        var cgroups = new AppCgroupManager(h.Fs);
        var engine = new BpfEngine(h.Bpftool, h.BpfPaths, h.Inodes, cgroups, null, _ => null, _ => null, new CollectingSink(), privileged: true, h.Time) { Log = h.Log.Add, ReconcileBackoff = TimeSpan.FromMilliseconds(1) };
        using var adapter = new NftFirewallPolicyAdapter(new NftEnginePaths(Path.Combine(h.Dir.Path, "filter")), new NftTable(h.Nft), cgroups, new CollectingSink(), () => true, h.Time) { VerdictLayer = engine };
        var supervisor = Supervise(h, adapter, engine);
        using var cts = new CancellationTokenSource();
        var run = supervisor.RunAsync(cts.Token);
        await WaitUntilAsync(() => engine.Active && engine.AppliedEntries.Count == 2);

        Assert.Contains(supervisor.OrphansReconciled, line => line.Contains("table inet axiom generation", StringComparison.Ordinal));
        Assert.Contains(supervisor.OrphansReconciled, line => line.Contains("axiom.slice/a-orphan", StringComparison.Ordinal));
        Assert.DoesNotContain("axiom.slice/a-orphan", h.Fs.Cgroups);
        Assert.False(h.Fs.Processes[700].Cgroup.StartsWith("axiom.slice", StringComparison.Ordinal));
        Assert.Contains(h.Log, line => line.Contains("reconciled orphaned state from a previous daemon", StringComparison.Ordinal));
        Assert.Equal(4, AxiomAttachments(h.Bpftool)); // the old four were detached, not stacked
        Assert.StartsWith("axiom.slice/a-", h.Fs.Processes[600].Cgroup, StringComparison.Ordinal);

        await cts.CancelAsync();
        await run;
        engine.Dispose();
        Assert.Equal(0, AxiomAttachments(h.Bpftool));
        // The origin cgroup of a pid herded by the killed daemon is not persisted: it goes back to its
        // parent's cgroup, else the root (documented in LINUX_ENFORCEMENT.md), never stays in axiom.slice.
        Assert.False(h.Fs.Processes[600].Cgroup.StartsWith("axiom.slice", StringComparison.Ordinal));
        Assert.DoesNotContain(h.Fs.Cgroups, cgroup => cgroup.StartsWith("axiom.slice/", StringComparison.Ordinal));
        Assert.Contains("system.slice/cron.service", h.Fs.Cgroups);
        AssertThirdPartyUntouched(h);
    }

    [Fact]
    public async Task Nft_delete_failure_in_teardown_still_detaches_bpf_and_releases_cgroups()
    {
        using var h = NewHarness();
        h.Fs.Cgroups.Add("system.slice/cron.service");
        h.Fs.Processes[600] = ("/usr/bin/curl", "system.slice/cron.service");
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        var supervisor = Supervise(h, h.Adapter, h.Engine);
        using var cts = new CancellationTokenSource();
        var run = supervisor.RunAsync(cts.Token);
        await WaitUntilAsync(() => h.Engine.Active && h.Fs.Processes[600].Cgroup.StartsWith("axiom.slice/", StringComparison.Ordinal));
        h.Nft.DeleteError = "Error: Could not process rule: Device or resource busy";

        await cts.CancelAsync();
        await run;

        var error = Assert.Single(supervisor.TeardownErrors);
        Assert.Contains("delete table inet axiom", error, StringComparison.Ordinal);
        Assert.Contains("Device or resource busy", error, StringComparison.Ordinal);
        Assert.Equal(0, AxiomAttachments(h.Bpftool));
        Assert.Equal("system.slice/cron.service", h.Fs.Processes[600].Cgroup);
        Assert.DoesNotContain(h.Fs.Cgroups, cgroup => cgroup.StartsWith("axiom.slice/", StringComparison.Ordinal));
        Assert.Contains(h.Log, line => line.StartsWith("Teardown finished with 1 error", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Hung_teardown_step_is_bounded_and_the_other_steps_still_run()
    {
        using var h = NewHarness();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        var layer = new RecordingLayer { Active = true, StopHangs = true };
        h.Adapter.VerdictLayer = layer;
        var supervisor = new NftEnforcementSupervisor(h.Adapter, new NftTable(h.Nft), null, layer, h.Log.Add, h.Time)
        {
            AttributionInterval = TimeSpan.FromSeconds(30),
            WatchInterval = TimeSpan.FromSeconds(30),
            TeardownStepTimeout = TimeSpan.FromMilliseconds(100),
        };
        using var cts = new CancellationTokenSource();
        var run = supervisor.RunAsync(cts.Token);
        await Task.Delay(50);
        await cts.CancelAsync();
        await run.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Contains(supervisor.TeardownErrors, error => error.Contains("timed out", StringComparison.Ordinal));
        Assert.Null(h.Nft.TableGeneration);
        Assert.DoesNotContain(h.Fs.Cgroups, cgroup => cgroup.StartsWith("axiom.slice/", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Loop_fault_is_logged_first_then_teardown_errors_and_the_fault_is_rethrown()
    {
        using var h = NewHarness();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        var layer = new RecordingLayer { Active = true, EventsFailure = new InvalidOperationException("simulated events fault"), StopFailure = new IOException("simulated bpf stop failure") };
        h.Adapter.VerdictLayer = layer;
        var supervisor = new NftEnforcementSupervisor(h.Adapter, new NftTable(h.Nft), null, layer, h.Log.Add, h.Time)
        {
            AttributionInterval = TimeSpan.FromSeconds(30),
            WatchInterval = TimeSpan.FromSeconds(30),
        };

        var fault = await Assert.ThrowsAsync<InvalidOperationException>(() => supervisor.RunAsync(CancellationToken.None));

        Assert.Equal("simulated events fault", fault.Message);
        Assert.Same(fault, supervisor.LastFault);
        var faultLine = h.Log.FindIndex(line => line.Contains("simulated events fault", StringComparison.Ordinal));
        var teardownLine = h.Log.FindIndex(line => line.Contains("simulated bpf stop failure", StringComparison.Ordinal));
        Assert.True(faultLine >= 0 && teardownLine > faultLine, "original fault logged before the teardown errors");
        Assert.Null(h.Nft.TableGeneration);
    }
}
