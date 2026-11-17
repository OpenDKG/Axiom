// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Bpf;
using Axiom.Infrastructure.Linux.Nft;
using Axiom.Infrastructure.Linux.Systemd;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

/// <summary>
/// Startup enforcement gap (docs/LINUX_EBPF.md §12): a daemon that starts after a crash or a
/// <c>systemctl restart</c> must not open a window in which a program blocked by a connect-time
/// proven rule can connect. The fake bpftool models program sets by pin identity, so the oracle
/// <see cref="FakeBpftool.Blocks"/> answers "would a fresh exec of curl be refused" after every
/// attach/detach the daemon makes.
/// </summary>
public sealed class BpfHandoverTests
{
    private static readonly Guid RuleA = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");
    private static readonly string CurlKey = BpfLayout.HexString(BpfLayout.ExeKey(8, 2, 51643045));

    /// <summary>A second daemon instance over the same rules, pins and kernel (the first one died).</summary>
    private sealed class NextDaemon : IDisposable
    {
        public NextDaemon(BpfEffectiveStateTests.Harness h)
        {
            var cgroups = new AppCgroupManager(h.Fs);
            Engine = new BpfEngine(h.Bpftool, h.BpfPaths, h.Inodes, cgroups, null, _ => null, _ => null, new CollectingSink(), privileged: true, h.Time) { Log = h.Log.Add, ReconcileBackoff = TimeSpan.FromMilliseconds(1) };
            Adapter = new NftFirewallPolicyAdapter(new NftEnginePaths(Path.Combine(h.Dir.Path, "filter")), new NftTable(h.Nft), cgroups, new CollectingSink(), () => true, h.Time) { VerdictLayer = Engine };
        }

        public BpfEngine Engine { get; }

        public NftFirewallPolicyAdapter Adapter { get; }

        public void Dispose()
        {
            Engine.Dispose();
            Adapter.Dispose();
        }
    }

    private static NftEnforcementSupervisor Supervise(BpfEffectiveStateTests.Harness h, NftFirewallPolicyAdapter adapter, BpfEngine engine, Func<bool>? keepLayerOnStop = null) =>
        new(adapter, new NftTable(h.Nft), null, engine, h.Log.Add, h.Time)
        {
            AttributionInterval = TimeSpan.FromMilliseconds(10),
            WatchInterval = TimeSpan.FromMilliseconds(15),
            TeardownStepTimeout = TimeSpan.FromSeconds(2),
            KeepLayerOnStop = keepLayerOnStop,
        };

    private static int AxiomAttachments(FakeBpftool bpftool) =>
        bpftool.Attached.Values.Count(program => program.Name.StartsWith("axiom_", StringComparison.Ordinal));

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 500 && !condition(); i++)
        {
            await Task.Delay(10);
        }

        Assert.True(condition(), "condition not reached within 5 s");
    }

    /// <summary>Old daemon: layer attached, curl blocked at connect time.</summary>
    private static async Task<BpfEffectiveStateTests.Harness> BlockedCurlAsync()
    {
        var h = new BpfEffectiveStateTests.Harness();
        h.Bpftool.Attached[7] = ("sd_fw_egress", "cgroup_inet_egress");
        await h.AttachAsync();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        Assert.True(h.Bpftool.Blocks(CurlKey), "precondition: the first daemon blocks curl at connect time");
        return h;
    }

    /// <summary>Records every attach/detach after which a fresh curl exec would have connected.</summary>
    private static List<string> WatchForGaps(FakeBpftool bpftool)
    {
        var gaps = new List<string>();
        bpftool.AfterChange = line =>
        {
            if (!bpftool.Blocks(CurlKey))
            {
                gaps.Add(line);
            }
        };
        return gaps;
    }

    [Fact]
    public async Task Crash_restart_keeps_blocking_until_the_new_set_is_attached_and_populated()
    {
        using var h = await BlockedCurlAsync();
        var gaps = WatchForGaps(h.Bpftool);

        // SIGKILL: no teardown. The next daemon starts over the same pins and kernel state.
        using var next = new NextDaemon(h);
        var supervisor = Supervise(h, next.Adapter, next.Engine);
        using var cts = new CancellationTokenSource();
        var run = supervisor.RunAsync(cts.Token);
        await WaitUntilAsync(() => next.Engine.Active && next.Engine.AppliedEntries.Count == 2);

        Assert.Empty(gaps);
        Assert.True(h.Bpftool.Blocks(CurlKey));
        Assert.Equal(4, AxiomAttachments(h.Bpftool));
        Assert.Equal(1, h.Bpftool.AttachedSets);
        Assert.InRange(h.Bpftool.MaxAxiomAttached, 4, 8); // old + new overlap only, never a third set
        Assert.True(Directory.Exists(h.BpfPaths.PinDirectory));
        Assert.False(Directory.Exists(h.BpfPaths.PinDirectory + ".next"));
        Assert.True(File.Exists(h.BpfPaths.MapPin(BpfLayout.ExeMap)));
        Assert.True(next.Engine.Generation >= 0);

        // The live set is reachable through the canonical pins: a removal really stops blocking.
        Assert.True((await next.Adapter.RemoveOwnedRuleAsync(RuleA, CancellationToken.None)).Success);
        Assert.False(h.Bpftool.Blocks(CurlKey));

        h.Bpftool.AfterChange = null;
        await cts.CancelAsync();
        await run;
        Assert.Equal(0, AxiomAttachments(h.Bpftool));
        Assert.False(Directory.Exists(h.BpfPaths.PinDirectory));
        Assert.False(Directory.Exists(h.BpfPaths.PinDirectory + ".next"));
        Assert.Equal(("sd_fw_egress", "cgroup_inet_egress"), h.Bpftool.Attached[7]);
    }

    [Fact]
    public async Task Restart_hands_the_layer_over_and_the_next_daemon_replaces_it_without_a_gap()
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        var first = Supervise(h, h.Adapter, h.Engine, keepLayerOnStop: () => true);
        using (var cts = new CancellationTokenSource())
        {
            var run = first.RunAsync(cts.Token);
            await WaitUntilAsync(() => h.Engine.Active && h.Engine.AppliedEntries.Count == 2);
            var gaps = WatchForGaps(h.Bpftool);

            // systemctl restart: the stop half must leave connect-time blocking in place.
            await cts.CancelAsync();
            await run;
            Assert.Empty(gaps);
            Assert.True(h.Bpftool.Blocks(CurlKey));
            Assert.Equal(4, AxiomAttachments(h.Bpftool));
            Assert.True(File.Exists(h.BpfPaths.MapPin(BpfLayout.ExeMap)));
            Assert.False(h.Engine.Active);
            Assert.StartsWith("handed over", h.Engine.Status, StringComparison.Ordinal);
            Assert.Contains(h.Log, line => line.Contains("left attached for the next daemon", StringComparison.Ordinal));
        }

        var gapsOnStart = WatchForGaps(h.Bpftool);
        using var next = new NextDaemon(h);
        var second = Supervise(h, next.Adapter, next.Engine);
        using var cts2 = new CancellationTokenSource();
        var run2 = second.RunAsync(cts2.Token);
        await WaitUntilAsync(() => next.Engine.Active && next.Engine.AppliedEntries.Count == 2);
        Assert.Empty(gapsOnStart);
        Assert.Equal(4, AxiomAttachments(h.Bpftool));
        Assert.Equal(1, h.Bpftool.AttachedSets);
        h.Bpftool.AfterChange = null;
        await cts2.CancelAsync();
        await run2;
    }

    [Fact]
    public async Task Plain_stop_still_detaches_everything_and_removes_both_pin_trees()
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        var supervisor = Supervise(h, h.Adapter, h.Engine, keepLayerOnStop: () => false);
        using var cts = new CancellationTokenSource();
        var run = supervisor.RunAsync(cts.Token);
        await WaitUntilAsync(() => h.Engine.Active && h.Engine.AppliedEntries.Count == 2);
        await cts.CancelAsync();
        await run;

        Assert.Equal(0, AxiomAttachments(h.Bpftool));
        Assert.False(Directory.Exists(h.BpfPaths.PinDirectory));
        Assert.False(Directory.Exists(h.BpfPaths.PinDirectory + ".next"));
        Assert.Equal("stopped", h.Engine.Status);
    }

    [Fact]
    public async Task Status_is_pending_not_verified_until_the_new_set_is_cut_over()
    {
        using var h = await BlockedCurlAsync();
        using var next = new NextDaemon(h);

        // IPC answers before the layer started: nothing about connect-time blocking is verified yet.
        await next.Adapter.PublishAsync(CancellationToken.None);
        var beforeStart = await next.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal("pending", beforeStart.ConnectTimeLayer!.State);
        Assert.False(beforeStart.ConnectTimeLayer.Healthy);
        Assert.Empty(beforeStart.ConnectTimeLayer.ConnectTimeProvenRules);
        Assert.NotEqual(FilterEnforcementState.Verified, beforeStart.FilterEnforcement!.State);

        // New set loaded and attached next to the old one, maps not yet written: still pending.
        await next.Engine.StartAsync(CancellationToken.None);
        Assert.False(next.Engine.Active);
        Assert.True(next.Engine.Pending);
        Assert.StartsWith("pending", next.Engine.Status, StringComparison.Ordinal);
        Assert.Equal(8, AxiomAttachments(h.Bpftool));
        Assert.True(h.Bpftool.Blocks(CurlKey));
        var during = await next.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal("pending", during.ConnectTimeLayer!.State);
        Assert.Empty(during.ConnectTimeLayer.ConnectTimeProvenRules);
        Assert.NotEqual(FilterEnforcementState.Verified, during.FilterEnforcement!.State);

        // Populated, read back, old set retired: now (and only now) verified.
        await next.Adapter.ResyncLayerAsync(CancellationToken.None);
        Assert.True(next.Engine.Active);
        Assert.False(next.Engine.Pending);
        Assert.Equal(4, AxiomAttachments(h.Bpftool));
        var after = await next.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal("active", after.ConnectTimeLayer!.State);
        Assert.Contains(RuleA, after.ConnectTimeLayer.ConnectTimeProvenRules);
        Assert.Equal(FilterEnforcementState.Verified, after.FilterEnforcement!.State);
    }

    [Fact]
    public async Task Old_set_that_cannot_be_fully_detached_keeps_the_new_set_and_never_loads_a_third()
    {
        using var h = await BlockedCurlAsync();
        var root = h.BpfPaths.CgroupRoot;
        h.Bpftool.FailPrefixes.Add($"bpftool cgroup detach {root} connect4 id ");
        var gaps = WatchForGaps(h.Bpftool);
        using var next = new NextDaemon(h);
        await next.Adapter.PublishAsync(CancellationToken.None);
        var supervisor = Supervise(h, next.Adapter, next.Engine);

        await supervisor.StartLayerAsync(CancellationToken.None);
        var loads = h.Bpftool.Loads;
        for (var tick = 0; tick < 3; tick++)
        {
            Assert.True(next.Engine.Active); // the new, populated set enforces
            Assert.True(next.Engine.StaleProgramsAttached); // the old connect4 refused to detach
            Assert.Equal(5, AxiomAttachments(h.Bpftool));
            Assert.True(h.Bpftool.Blocks(CurlKey));
            var report = await next.Adapter.GetCapabilitiesAsync(CancellationToken.None);
            Assert.Equal(FilterEnforcementState.Degraded, report.FilterEnforcement!.State);
            Assert.Equal("stale_programs", report.ConnectTimeLayer!.State);
            await supervisor.WatchOnceAsync(CancellationToken.None);
            Assert.Equal(loads, h.Bpftool.Loads); // retries the detach only
        }

        h.Bpftool.FailPrefixes.Clear();
        await supervisor.WatchOnceAsync(CancellationToken.None);
        Assert.False(next.Engine.StaleProgramsAttached);
        Assert.Equal(4, AxiomAttachments(h.Bpftool));
        Assert.Equal(1, h.Bpftool.AttachedSets);
        Assert.False(Directory.Exists(h.BpfPaths.PinDirectory + ".next"));
        Assert.True(File.Exists(h.BpfPaths.MapPin(BpfLayout.ExeMap)));
        Assert.Empty(gaps);
        Assert.InRange(h.Bpftool.MaxAxiomAttached, 4, 8);
        var healed = await next.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal("active", healed.ConnectTimeLayer!.State);
    }

    [Fact]
    public async Task New_set_whose_maps_cannot_be_populated_is_rolled_back_and_the_old_set_keeps_enforcing()
    {
        using var h = await BlockedCurlAsync();
        var staging = h.BpfPaths.PinDirectory + ".next";
        h.Bpftool.FailPrefixes.Add($"bpftool map update pinned {Path.Combine(staging, "maps", BpfLayout.ExeMap)}");
        var gaps = WatchForGaps(h.Bpftool);
        using var next = new NextDaemon(h);
        await next.Adapter.PublishAsync(CancellationToken.None);
        var supervisor = Supervise(h, next.Adapter, next.Engine);

        for (var tick = 0; tick < 3; tick++)
        {
            if (tick == 0)
            {
                await supervisor.StartLayerAsync(CancellationToken.None);
            }
            else
            {
                await supervisor.WatchOnceAsync(CancellationToken.None);
            }

            Assert.False(next.Engine.Active);
            Assert.True(next.Engine.StaleProgramsAttached);
            Assert.Equal(4, AxiomAttachments(h.Bpftool)); // the previous daemon's set only
            Assert.False(Directory.Exists(staging));
            Assert.True(h.Bpftool.Blocks(CurlKey));
        }

        Assert.Empty(gaps);
        Assert.InRange(h.Bpftool.MaxAxiomAttached, 4, 8);
        var report = await next.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FilterEnforcementState.Degraded, report.FilterEnforcement!.State);
        Assert.Equal("stale_programs", report.ConnectTimeLayer!.State);
    }

    [Fact]
    public async Task Unreadable_attachment_state_at_start_loads_nothing_detaches_nothing_and_keeps_the_pins()
    {
        using var h = await BlockedCurlAsync();
        h.Bpftool.CgroupShowOutput = "garbage";
        var loads = h.Bpftool.Loads;
        var calls = h.Bpftool.Calls.Count;
        using var next = new NextDaemon(h);
        await next.Engine.StartAsync(CancellationToken.None);

        Assert.Equal(loads, h.Bpftool.Loads);
        Assert.DoesNotContain(h.Bpftool.Calls.Skip(calls), call => call.Contains("cgroup detach", StringComparison.Ordinal));
        Assert.True(next.Engine.AttachmentUnknown);
        Assert.False(next.Engine.Active);
        Assert.False(next.Engine.Pending);
        Assert.StartsWith("unknown", next.Engine.Status, StringComparison.Ordinal);
        Assert.True(File.Exists(h.BpfPaths.ProgramPin("axiom_connect4")));
        Assert.True(h.Bpftool.Blocks(CurlKey));
    }

    [Fact]
    public async Task A_rule_removed_before_the_crash_stops_blocking_once_the_new_set_takes_over()
    {
        using var h = await BlockedCurlAsync();

        // The old set's maps still hold A (a removal whose BPF cleanup never ran); the stored rules do not.
        var stored = Path.Combine(h.Dir.Path, "filter");
        using (var editor = new NextDaemon(h))
        {
            editor.Adapter.VerdictLayer = null;
            Assert.True((await editor.Adapter.RemoveOwnedRuleAsync(RuleA, CancellationToken.None)).Success);
        }

        Assert.True(h.Bpftool.Blocks(CurlKey));
        using var next = new NextDaemon(h);
        var supervisor = Supervise(h, next.Adapter, next.Engine);
        using var cts = new CancellationTokenSource();
        var run = supervisor.RunAsync(cts.Token);
        await WaitUntilAsync(() => next.Engine.Active);
        Assert.False(h.Bpftool.Blocks(CurlKey));
        Assert.Equal(4, AxiomAttachments(h.Bpftool));
        Assert.True(Directory.Exists(stored));
        await cts.CancelAsync();
        await run;
    }

    [Fact]
    public async Task Two_sets_already_attached_at_start_never_get_a_third()
    {
        using var h = await BlockedCurlAsync();
        var root = h.BpfPaths.CgroupRoot;

        // An earlier failure left a second, unpinned set attached.
        foreach (var (hook, program) in BpfLayout.Programs)
        {
            h.Bpftool.Attached[500 + h.Bpftool.Attached.Count] = (program, hook);
        }

        Assert.Equal(8, AxiomAttachments(h.Bpftool));
        using var next = new NextDaemon(h);
        var supervisor = Supervise(h, next.Adapter, next.Engine);
        using var cts = new CancellationTokenSource();
        var run = supervisor.RunAsync(cts.Token);
        await WaitUntilAsync(() => next.Engine.Active);
        Assert.Equal(4, AxiomAttachments(h.Bpftool));
        Assert.InRange(h.Bpftool.MaxAxiomAttached, 4, 8);
        Assert.DoesNotContain(h.Bpftool.Calls, call => call.Contains($"detach {root} ", StringComparison.Ordinal) && call.EndsWith(" id 7", StringComparison.Ordinal));
        await cts.CancelAsync();
        await run;
    }

    [Fact]
    public void Systemd_job_list_tells_a_restart_from_a_stop_and_unreadable_output_keeps_enforcement()
    {
        Assert.True(SystemdStopIntent.Classify("812 axiomd.service restart running\n", "axiomd.service"));
        Assert.True(SystemdStopIntent.Classify("812 axiomd.service try-restart running\n", "axiomd.service"));
        Assert.False(SystemdStopIntent.Classify("813 axiomd.service stop running\n", "axiomd.service"));
        Assert.False(SystemdStopIntent.Classify(string.Empty, "axiomd.service"));
        Assert.False(SystemdStopIntent.Classify("No jobs running.\n", "axiomd.service"));
        Assert.False(SystemdStopIntent.Classify("9 other.service restart running\n", "axiomd.service"));
        Assert.Null(SystemdStopIntent.Classify("812 axiomd.service\n", "axiomd.service"));
        Assert.Null(SystemdStopIntent.Classify("812 axiomd.service frobnicate running\n", "axiomd.service"));
    }

    [Fact]
    public void Stop_intent_keeps_enforcement_for_a_restart_an_upgrade_marker_or_an_unreadable_systemctl()
    {
        using var temp = new TempDirectory();
        var marker = Path.Combine(temp.Path, SystemdStopIntent.MarkerFileName);
        var log = new List<string>();
        var answer = new Axiom.Infrastructure.Unix.Interop.ProcessResult(0, "813 axiomd.service stop running\n", string.Empty);
        var runner = new ScriptedRunner(_ => answer);
        var intent = new SystemdStopIntent(runner, marker, log.Add);

        Assert.False(intent.KeepEnforcementAcrossStop());
        Assert.Contains(runner.Calls, call => call.Contains("list-jobs", StringComparison.Ordinal));

        answer = new Axiom.Infrastructure.Unix.Interop.ProcessResult(0, "812 axiomd.service restart running\n", string.Empty);
        Assert.True(intent.KeepEnforcementAcrossStop());

        answer = new Axiom.Infrastructure.Unix.Interop.ProcessResult(1, string.Empty, "Failed to connect to bus");
        Assert.True(intent.KeepEnforcementAcrossStop());
        Assert.Contains(log, line => line.Contains("cannot tell", StringComparison.Ordinal));

        answer = new Axiom.Infrastructure.Unix.Interop.ProcessResult(0, "813 axiomd.service stop running\n", string.Empty);
        File.WriteAllText(marker, "upgrade\n");
        Assert.True(intent.KeepEnforcementAcrossStop());
        Assert.False(File.Exists(marker)); // one-shot
    }

    [Fact]
    public void Doctor_does_not_pass_live_enforcement_while_the_connect_time_layer_is_still_pending()
    {
        using var temp = new TempDirectory();
        var targets = new Axiom.Infrastructure.Linux.Diagnostics.LinuxDoctorTargets(
            Path.Combine(temp.Path, "axiomd.service"),
            Path.Combine(temp.Path, "image"),
            Path.Combine(temp.Path, "data"),
            Path.Combine(temp.Path, "axiom.sock"),
            Path.Combine(temp.Path, "backup.json"),
            Path.Combine(temp.Path, "protection.json"),
            Path.Combine(temp.Path, "vmlinux"),
            Path.Combine(temp.Path, "pins"));
        var live = new FirewallCapabilityReport
        {
            Status = FirewallCapabilityStatus.Available,
            FilterEnforcement = new FilterEnforcementReport { State = FilterEnforcementState.Pending },
            ConnectTimeLayer = new ConnectTimeLayerReport { State = "pending", Healthy = false, Attached = false, Status = "pending: a new program set is attached next to 4 program(s) of a previous daemon" },
        };
        var doctor = new Axiom.Infrastructure.Linux.Diagnostics.LinuxDoctor(new LiveStateAndCoverageTests.ActiveUnitRunner(new FakeBpftool(Path.Combine(temp.Path, "pins"))), targets, isRoot: true, () => new Axiom.Infrastructure.Linux.Diagnostics.DoctorLiveState(live, null));

        var checks = doctor.Collect();

        var enforcement = checks.Single(check => check.Name == "live enforcement");
        Assert.Equal(Axiom.Infrastructure.Unix.Diagnostics.DoctorCheck.Warn, enforcement.Status);
        Assert.Contains("pending", enforcement.Detail, StringComparison.Ordinal);
        Assert.Contains("not verified", enforcement.Detail, StringComparison.Ordinal);
        Assert.Equal(Axiom.Infrastructure.Unix.Diagnostics.DoctorCheck.Warn, checks.Single(check => check.Name == "bpf layer").Status);
    }

    private sealed class ScriptedRunner(Func<string, Axiom.Infrastructure.Unix.Interop.ProcessResult> answer) : Axiom.Infrastructure.Unix.Interop.IProcessRunner
    {
        public List<string> Calls { get; } = [];

        public Axiom.Infrastructure.Unix.Interop.ProcessResult Run(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout)
        {
            var line = fileName + " " + string.Join(' ', arguments);
            Calls.Add(line);
            return answer(line);
        }
    }
}
