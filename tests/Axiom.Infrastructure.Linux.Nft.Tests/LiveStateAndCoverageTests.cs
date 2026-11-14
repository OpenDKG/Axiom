// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Bpf;
using Axiom.Infrastructure.Linux.Diagnostics;
using Axiom.Infrastructure.Linux.Nft;
using Axiom.Infrastructure.Unix.Diagnostics;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

/// <summary>
/// PR #276 review round 3 (2026-11-14): #290 (the doctor must read the live layer state, not pin
/// files), the restart-while-pending false clear, and the per-rule coverage split between
/// "nft rule installed/read back" and "new-process connect-time blocking proven".
/// </summary>
public sealed class LiveStateAndCoverageTests
{
    private static readonly Guid RuleA = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");
    private static readonly Guid RuleB = Guid.Parse("7c9e6679-7425-40de-944b-e07fc1f90ae7");
    private const long ThirdPartyProgram = 7;

    private static int AxiomAttachments(FakeBpftool bpftool) =>
        bpftool.Attached.Values.Count(program => program.Name.StartsWith("axiom_", StringComparison.Ordinal));

    /// <summary>A second daemon process over the same state directory, pins and (fake) kernel.</summary>
    private sealed class Restarted : IDisposable
    {
        public Restarted(BpfEffectiveStateTests.Harness h)
        {
            var cgroups = new AppCgroupManager(h.Fs);
            Engine = new BpfEngine(h.Bpftool, h.BpfPaths, h.Inodes, cgroups, null, _ => null, _ => null, new CollectingSink(), privileged: true, h.Time) { Log = h.Log.Add, ReconcileBackoff = TimeSpan.FromMilliseconds(1) };
            Adapter = new NftFirewallPolicyAdapter(new NftEnginePaths(Path.Combine(h.Dir.Path, "filter")), new NftTable(h.Nft), cgroups, new CollectingSink(), () => true, h.Time)
            {
                VerdictLayer = Engine,
            };
            Supervisor = new NftEnforcementSupervisor(Adapter, new NftTable(h.Nft), null, Engine, h.Log.Add, h.Time);
        }

        public BpfEngine Engine { get; }

        public NftFirewallPolicyAdapter Adapter { get; }

        public NftEnforcementSupervisor Supervisor { get; }

        public async Task StartAsync()
        {
            await Supervisor.ReconcileOrphansAsync(CancellationToken.None);
            await Adapter.PublishAsync(CancellationToken.None);
            await Adapter.RefreshAsync(CancellationToken.None);
            await Supervisor.StartLayerAsync(CancellationToken.None);
        }

        public void Dispose()
        {
            Engine.Dispose();
            Adapter.Dispose();
        }
    }

    [Fact]
    public async Task Restart_while_a_removal_is_pending_and_delete_plus_detach_keep_failing_never_reports_a_clean_layer()
    {
        using var h = new BpfEffectiveStateTests.Harness();
        h.Bpftool.Attached[ThirdPartyProgram] = ("sd_fw_egress", "cgroup_inet_egress");
        await h.AttachAsync();
        Assert.True((await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None)).Success);
        h.Bpftool.FailPrefixes.Add("bpftool map delete");
        h.Bpftool.FailPrefixes.Add("bpftool cgroup detach");

        var removal = await h.Adapter.RemoveOwnedRuleAsync(RuleA, CancellationToken.None);
        Assert.Equal("bpf.stale_entry", removal.ErrorCode);
        var before = await h.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Contains(RuleA, before.ConnectTimeLayer!.PendingRemovals);

        // systemctl restart axiomd while the fault persists: the old daemon's programs stay attached.
        using var next = new Restarted(h);
        await next.StartAsync();

        Assert.False(next.Engine.Active);
        Assert.True(next.Engine.StaleProgramsAttached);
        Assert.Equal(4, AxiomAttachments(h.Bpftool)); // no second set loaded on top of the stale one
        var capabilities = await next.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FirewallCapabilityStatus.Degraded, capabilities.Status);
        Assert.Equal(FilterEnforcementState.Degraded, capabilities.FilterEnforcement!.State);
        Assert.Equal("stale_programs", capabilities.ConnectTimeLayer!.State);
        Assert.False(capabilities.ConnectTimeLayer.Healthy);
        Assert.Contains(RuleA, capabilities.ConnectTimeLayer.PendingRemovals);
        Assert.Contains("could not be detached", capabilities.Reason, StringComparison.Ordinal);
        Assert.True(h.Bpftool.Attached.ContainsKey(ThirdPartyProgram));

        // Fault over: the watch tick detaches the stale set, loads a fresh one, and only then clears the removal.
        h.Bpftool.FailPrefixes.Clear();
        await next.Supervisor.WatchOnceAsync(CancellationToken.None);
        Assert.True(next.Engine.Active);
        Assert.False(next.Engine.StaleProgramsAttached);
        Assert.Equal(4, AxiomAttachments(h.Bpftool));
        var healed = await next.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FirewallCapabilityStatus.Available, healed.Status);
        Assert.True(healed.ConnectTimeLayer!.Healthy);
        Assert.Empty(healed.ConnectTimeLayer.PendingRemovals);
        Assert.True(h.Bpftool.Attached.ContainsKey(ThirdPartyProgram));
    }

    [Fact]
    public async Task Pending_removal_survives_a_restart_while_bpftool_is_unusable()
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.AttachAsync();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        h.Bpftool.FailPrefixes.Add("bpftool map delete");
        h.Bpftool.FailPrefixes.Add("bpftool cgroup detach");
        await h.Adapter.RemoveOwnedRuleAsync(RuleA, CancellationToken.None);

        h.Bpftool.FailPrefixes.Add("bpftool version"); // the probe now says no: nothing can be confirmed
        using var next = new Restarted(h);
        await next.StartAsync();

        var capabilities = await next.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FirewallCapabilityStatus.Degraded, capabilities.Status);
        Assert.Contains(RuleA, capabilities.ConnectTimeLayer!.PendingRemovals);
        Assert.Contains("not confirmed", capabilities.Reason, StringComparison.Ordinal);
    }

    // ---------------- #290: axiomd --doctor ----------------

    private sealed class ActiveUnitRunner(FakeBpftool bpftool) : IProcessRunner
    {
        public ProcessResult Run(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout) =>
            Path.GetFileName(fileName) == "systemctl" && arguments.Count > 0 && arguments[0] == "is-active"
                ? new ProcessResult(0, "active\n", string.Empty)
                : bpftool.Run(fileName, arguments, timeout);
    }

    private static (LinuxDoctorTargets Targets, FakeBpftool Bpftool, TempDirectory Temp) DoctorFixture()
    {
        var temp = new TempDirectory();
        var image = Path.Combine(temp.Path, "image");
        Directory.CreateDirectory(Path.Combine(image, "bpf"));
        File.WriteAllText(Path.Combine(image, "bpf", BpfEnginePaths.ObjectFileName), string.Empty);
        var btf = Path.Combine(temp.Path, "vmlinux");
        File.WriteAllText(btf, string.Empty);
        var pins = Path.Combine(temp.Path, "pins");
        Directory.CreateDirectory(pins);
        foreach (var (_, program) in BpfLayout.Programs)
        {
            File.WriteAllText(Path.Combine(pins, program), string.Empty); // four stale pin files
        }

        var targets = new LinuxDoctorTargets(
            Path.Combine(temp.Path, "axiomd.service"),
            image,
            Path.Combine(temp.Path, "data"),
            Path.Combine(temp.Path, "axiom.sock"),
            Path.Combine(temp.Path, "backup.json"),
            Path.Combine(temp.Path, "protection.json"),
            btf,
            pins);
        return (targets, new FakeBpftool(pins), temp);
    }

    private static FirewallCapabilityReport Capability(FirewallCapabilityStatus status, ConnectTimeLayerReport layer, string? reason = null) => new()
    {
        Status = status,
        Reason = reason,
        ConnectTimeLayer = layer,
    };

    [Fact]
    public void Doctor_warns_when_the_live_layer_is_degraded_although_four_pins_exist_issue_290()
    {
        var (targets, bpftool, temp) = DoctorFixture();
        using var _ = temp;
        var live = Capability(
            FirewallCapabilityStatus.Degraded,
            new ConnectTimeLayerReport
            {
                State = "stale_programs",
                Healthy = false,
                Attached = true,
                Status = "degraded: 4 Axiom program(s) of a previous daemon could not be detached",
                PendingRemovals = [RuleA],
            },
            "BPF programs of a previous daemon could not be detached.");
        var doctor = new LinuxDoctor(new ActiveUnitRunner(bpftool), targets, isRoot: true, () => new DoctorLiveState(live, null));

        var checks = doctor.Collect();
        var bpf = checks.Single(check => check.Name == "bpf layer");
        Assert.Equal(DoctorCheck.Warn, bpf.Status);
        Assert.Contains("stale_programs", bpf.Detail, StringComparison.Ordinal);
        Assert.Contains(RuleA.ToString("D"), bpf.Detail, StringComparison.Ordinal);
        Assert.Contains(checks, check => check.Name == "live enforcement" && check.Status == DoctorCheck.Warn);

        using var output = new StringWriter();
        doctor.Write(checks.Where(check => check.Name is "bpf layer" or "live enforcement").ToList(), json: false, output);
        Assert.DoesNotContain("all checks passed", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Doctor_says_it_cannot_confirm_the_live_state_when_ipc_is_unavailable()
    {
        var (targets, bpftool, temp) = DoctorFixture();
        using var _ = temp;
        var doctor = new LinuxDoctor(new ActiveUnitRunner(bpftool), targets, isRoot: true, () => new DoctorLiveState(null, "connection refused"));

        var bpf = doctor.Collect().Single(check => check.Name == "bpf layer");
        Assert.Equal(DoctorCheck.Warn, bpf.Status);
        Assert.Contains("cannot confirm live state", bpf.Detail, StringComparison.Ordinal);
        Assert.Contains("connection refused", bpf.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Doctor_passes_only_with_a_healthy_live_layer()
    {
        var (targets, bpftool, temp) = DoctorFixture();
        using var _ = temp;
        var live = Capability(
            FirewallCapabilityStatus.Available,
            new ConnectTimeLayerReport { State = "active", Healthy = true, Attached = true, Generation = 12, MapsVerified = true, ConnectTimeProvenRules = [RuleA], NftOnlyRules = [RuleB] });
        var doctor = new LinuxDoctor(new ActiveUnitRunner(bpftool), targets, isRoot: true, () => new DoctorLiveState(live, null));

        var checks = doctor.Collect();
        var bpf = checks.Single(check => check.Name == "bpf layer");
        Assert.Equal(DoctorCheck.Pass, bpf.Status);
        Assert.Contains("generation 12", bpf.Detail, StringComparison.Ordinal);
        Assert.Contains("1 rule(s) nft-only", bpf.Detail, StringComparison.Ordinal);
        Assert.Contains(checks, check => check.Name == "live enforcement" && check.Status == DoctorCheck.Pass);
    }

    [Fact]
    public async Task Doctor_over_the_real_adapter_after_failed_delete_detach_and_restart_is_not_green()
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.AttachAsync();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        h.Bpftool.FailPrefixes.Add("bpftool map delete");
        h.Bpftool.FailPrefixes.Add("bpftool cgroup detach");
        await h.Adapter.RemoveOwnedRuleAsync(RuleA, CancellationToken.None);
        using var next = new Restarted(h);
        await next.StartAsync();

        var targets = new LinuxDoctorTargets(
            Path.Combine(h.Dir.Path, "axiomd.service"),
            Path.Combine(h.Dir.Path, "image"),
            Path.Combine(h.Dir.Path, "data"),
            Path.Combine(h.Dir.Path, "axiom.sock"),
            Path.Combine(h.Dir.Path, "backup.json"),
            Path.Combine(h.Dir.Path, "protection.json"),
            h.BpfPaths.BtfFile,
            h.BpfPaths.PinDirectory);
        var capability = await next.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        var doctor = new LinuxDoctor(new ActiveUnitRunner(h.Bpftool), targets, isRoot: true, () => new DoctorLiveState(capability, null));

        var checks = doctor.Collect().Where(check => check.Name is "bpf layer" or "live enforcement").ToList();
        Assert.All(checks, check => Assert.Equal(DoctorCheck.Warn, check.Status));
    }

    // ---------------- coverage: nft read back vs connect-time proven ----------------

    [Fact]
    public async Task Unscoped_outbound_block_with_an_attached_layer_is_connect_time_proven()
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.AttachAsync();
        var spec = Specs.Block("/usr/bin/curl", RuleA);

        var applied = await h.Adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);
        var verify = await h.Adapter.VerifyAsync(spec, CancellationToken.None);

        Assert.Equal(RuleState.Applied, applied.State);
        Assert.True(applied.ConnectTimeBlockingProven);
        Assert.True(verify.EnforcementVerified);
        Assert.True(verify.NftRuleReadBack);
        Assert.True(verify.ConnectTimeBlockingProven);
        var listed = Assert.Single(await h.Adapter.ListOwnedRulesAsync(CancellationToken.None));
        Assert.True(listed.ConnectTimeBlockingProven);
    }

    [Fact]
    public async Task Scoped_rule_is_read_back_in_nft_but_never_reported_race_free()
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.AttachAsync();
        var spec = Specs.Block("/usr/bin/curl", RuleA) with { RemotePorts = "443" };

        var applied = await h.Adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);
        var verify = await h.Adapter.VerifyAsync(spec, CancellationToken.None);

        Assert.Equal(RuleState.Applied, applied.State);
        Assert.False(applied.ConnectTimeBlockingProven);
        Assert.True(verify.EnforcementVerified);
        Assert.True(verify.NftRuleReadBack);
        Assert.False(verify.ConnectTimeBlockingProven);
        Assert.Contains("not race-free", verify.CoverageReason, StringComparison.Ordinal);
        Assert.Contains(verify.Notes, note => note.Contains("installed/read back, not race-free", StringComparison.Ordinal));
        var capabilities = await h.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Contains(RuleA, capabilities.ConnectTimeLayer!.NftOnlyRules);
        Assert.Contains(capabilities.Limitations, line => line.Contains("1 rule(s) are nft-only", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Without_a_connect_time_layer_every_rule_is_nft_only()
    {
        using var temp = new TempDirectory();
        var nft = new FakeNftRunner();
        var fs = new FakeCgroupFs();
        fs.AppPaths["/usr/bin/curl"] = "/usr/bin/curl";
        using var adapter = new NftFirewallPolicyAdapter(new NftEnginePaths(Path.Combine(temp.Path, "filter")), new NftTable(nft), new AppCgroupManager(fs), new CollectingSink(), () => true, TimeProvider.System);
        var spec = Specs.Block("/usr/bin/curl", RuleA);

        await adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);
        var verify = await adapter.VerifyAsync(spec, CancellationToken.None);

        Assert.True(verify.NftRuleReadBack);
        Assert.False(verify.ConnectTimeBlockingProven);
        Assert.Contains("no connect-time layer", verify.CoverageReason, StringComparison.Ordinal);
        var capabilities = await adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal("not_configured", capabilities.ConnectTimeLayer!.State);
    }

    [Fact]
    public async Task Unprovable_exe_key_is_nft_only_with_its_reason()
    {
        using var h = new BpfEffectiveStateTests.Harness();
        h.Inodes.Files.Remove("/usr/bin/curl");
        await h.AttachAsync();
        var spec = Specs.Block("/usr/bin/curl", RuleA);

        await h.Adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);
        var verify = await h.Adapter.VerifyAsync(spec, CancellationToken.None);

        Assert.False(verify.ConnectTimeBlockingProven);
        Assert.Contains("not race-free", verify.CoverageReason, StringComparison.Ordinal);
    }

    // ---------------- executable replacement (rename(2) over the blocked path) ----------------

    [Fact]
    public async Task Replaced_executable_is_not_reported_connect_time_proven_and_the_watch_tick_rekeys_it()
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.AttachAsync();
        var spec = Specs.Block("/usr/bin/curl", RuleA);
        await h.Adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);
        var exeMap = h.BpfPaths.MapPin(BpfLayout.ExeMap);
        var oldKey = BpfLayout.HexString(BpfLayout.ExeKey(8, 2, 51643045));
        Assert.Contains(oldKey, h.Bpftool.Map(exeMap).Keys);

        // dnf/apt upgrade: the new binary is written elsewhere and renamed over the path (new inode).
        h.Inodes.Files["/usr/bin/curl"] = new BpfInode(8, 2, 60000001);

        var verify = await h.Adapter.VerifyAsync(spec, CancellationToken.None);
        Assert.False(verify.ConnectTimeBlockingProven);
        Assert.Contains("replaced", verify.CoverageReason, StringComparison.Ordinal);

        var supervisor = new NftEnforcementSupervisor(h.Adapter, new NftTable(h.Nft), null, h.Engine, h.Log.Add, h.Time);
        await supervisor.WatchOnceAsync(CancellationToken.None);

        var newKey = BpfLayout.HexString(BpfLayout.ExeKey(8, 2, 60000001));
        Assert.Contains(newKey, h.Bpftool.Map(exeMap).Keys);
        Assert.DoesNotContain(oldKey, h.Bpftool.Map(exeMap).Keys);
        Assert.True((await h.Adapter.VerifyAsync(spec, CancellationToken.None)).ConnectTimeBlockingProven);
        Assert.Contains(h.Log, line => line.Contains("re-resolved", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Externally_detached_programs_are_noticed_by_verify_and_re_attached_by_the_watch_tick()
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.AttachAsync();
        var spec = Specs.Block("/usr/bin/curl", RuleA);
        Assert.True((await h.Adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None)).ConnectTimeBlockingProven);

        // `bpftool cgroup detach` by another tool (measured live: the canary then slips 99/100 fresh processes).
        foreach (var id in h.Bpftool.Attached.Where(pair => pair.Value.Name.StartsWith("axiom_", StringComparison.Ordinal)).Select(pair => pair.Key).ToList())
        {
            h.Bpftool.Attached.Remove(id);
        }

        var verify = await h.Adapter.VerifyAsync(spec, CancellationToken.None);
        Assert.False(verify.ConnectTimeBlockingProven);
        Assert.Contains("detached", verify.CoverageReason, StringComparison.Ordinal);

        var supervisor = new NftEnforcementSupervisor(h.Adapter, new NftTable(h.Nft), null, h.Engine, h.Log.Add, h.Time);
        await supervisor.WatchOnceAsync(CancellationToken.None);
        Assert.Equal(4, AxiomAttachments(h.Bpftool));
        Assert.True((await h.Adapter.VerifyAsync(spec, CancellationToken.None)).ConnectTimeBlockingProven);
    }
}
