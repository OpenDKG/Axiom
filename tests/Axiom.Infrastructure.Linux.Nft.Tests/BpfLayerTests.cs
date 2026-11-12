// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Axiom.Infrastructure.Linux.Bpf;
using Axiom.Infrastructure.Linux.Diagnostics;
using Axiom.Infrastructure.Linux.Systemd;
using Axiom.Infrastructure.Unix.Diagnostics;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

internal sealed class FakeInodes : IInodeReader
{
    public Dictionary<string, BpfInode> Files { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, ulong> CgroupIds { get; } = new(StringComparer.Ordinal);

    public BpfInode? Stat(string path) => Files.TryGetValue(path, out var inode) ? inode : null;

    public ulong? CgroupId(string cgroupPath) => CgroupIds.TryGetValue(cgroupPath, out var id) ? id : null;
}

/// <summary>Records bpftool invocations; `prog loadall` materialises the pins so the engine's file checks behave.</summary>
internal sealed class FakeBpftool(string pinDirectory) : IProcessRunner
{
    public List<string> Calls { get; } = [];

    public HashSet<string> FailPrefixes { get; } = new(StringComparer.Ordinal);

    public ProcessResult Run(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout)
    {
        var line = string.Join(' ', new[] { Path.GetFileName(fileName) }.Concat(arguments));
        Calls.Add(line);
        if (FailPrefixes.Any(prefix => line.StartsWith(prefix, StringComparison.Ordinal)))
        {
            return new ProcessResult(1, string.Empty, "Error: simulated failure\n");
        }

        if (line.StartsWith("bpftool version", StringComparison.Ordinal))
        {
            return new ProcessResult(0, "bpftool v7.4.0\nusing libbpf v1.4\n", string.Empty);
        }

        if (line.StartsWith("bpftool prog loadall", StringComparison.Ordinal))
        {
            Directory.CreateDirectory(Path.Combine(pinDirectory, "maps"));
            foreach (var (_, program) in BpfLayout.Programs)
            {
                File.WriteAllText(Path.Combine(pinDirectory, program), string.Empty);
            }

            foreach (var map in new[] { BpfLayout.ExeMap, BpfLayout.CgroupMap, BpfLayout.EventsMap, BpfLayout.StatsMap })
            {
                File.WriteAllText(Path.Combine(pinDirectory, "maps", map), string.Empty);
            }
        }

        return new ProcessResult(0, string.Empty, string.Empty);
    }
}

internal sealed class RecordingLayer : IEnforcementLayer
{
    public List<(int Rules, long Generation)> Syncs { get; } = [];

    public bool Started { get; private set; }

    public bool Stopped { get; private set; }

    public bool Active { get; set; }

    public string Status { get; set; } = "inactive: test";

    /// <summary>Fault seams for the supervisor tests.</summary>
    public Exception? StopFailure { get; set; }

    public Exception? EventsFailure { get; set; }

    public Task StartAsync(CancellationToken ct)
    {
        Started = true;
        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        Stopped = true;
        if (StopFailure is { } failure)
        {
            throw failure;
        }

        return Task.CompletedTask;
    }

    public async Task RunEventsAsync(CancellationToken ct)
    {
        if (EventsFailure is { } failure)
        {
            await Task.Yield();
            throw failure;
        }

        await Task.Delay(Timeout.Infinite, ct);
    }

    public Task SyncAsync(IReadOnlyList<ManagedRule> rules, long generation, CancellationToken ct)
    {
        Syncs.Add((rules.Count, generation));
        return Task.CompletedTask;
    }
}

public sealed class BpfLayerTests
{
    private static readonly Guid RuleA = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");

    [Fact]
    public void Layout_encodes_keys_and_verdicts_little_endian_and_round_trips_rule_ids()
    {
        var key = BpfLayout.ExeKey(8, 2, 51643045);
        Assert.Equal("08000000" + "02000000" + "a502140300000000", BpfLayout.HexString(key)); // 51643045 = 0x031402a5
        Assert.Equal(BpfLayout.ExeKeySize, key.Length);

        var cgroup = BpfLayout.CgroupKey(93);
        Assert.Equal("5d00000000000000", BpfLayout.HexString(cgroup));

        var verdict = BpfLayout.Verdict(BpfLayout.ActionBlock, BpfLayout.ProtoAny, 42, RuleA);
        Assert.Equal(BpfLayout.VerdictSize, verdict.Length);
        Assert.Equal(new byte[] { 0x02, 0x07, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00 }, verdict[..8]);
        Assert.Equal(RuleA.ToByteArray(), verdict[8..]);

        var tokens = BpfLayout.HexTokens(verdict);
        Assert.Equal(24, tokens.Count);
        Assert.Equal("02", tokens[0]);
        Assert.Equal("2a", tokens[4]);

        Assert.Equal(RuleA, BpfLayout.ParseRuleId(Convert.ToHexStringLower(RuleA.ToByteArray())));
        Assert.Null(BpfLayout.ParseRuleId(new string('0', 32)));
        Assert.Null(BpfLayout.ParseRuleId("zz"));
    }

    [Fact]
    public void Stat_output_parses_into_major_minor_inode()
    {
        Assert.Equal(new BpfInode(8, 2, 51643045), StatInodeReader.Parse("8 2 51643045\n"));
        Assert.Null(StatInodeReader.Parse("garbage"));
    }

    [Fact]
    public void Planner_keys_only_unscoped_outbound_block_rules_and_merges_protocols()
    {
        var fs = new FakeCgroupFs();
        fs.AppPaths["/usr/bin/curl"] = "/usr/bin/curl";
        fs.AppPaths["/usr/bin/wget"] = "/usr/bin/wget";
        var cgroups = new AppCgroupManager(fs);
        var inodes = new FakeInodes();
        inodes.Files["/usr/bin/curl"] = new BpfInode(8, 2, 51643045);
        inodes.Files["/usr/bin/wget"] = new BpfInode(8, 2, 777);
        Assert.True(cgroups.TryResolve("/usr/bin/curl", out var curlCgroup, out _));
        inodes.CgroupIds[curlCgroup] = 93;

        var scopedAddress = Specs.Block("/usr/bin/wget") with { RemoteAddresses = ["1.2.3.4"] };
        var scopedPort = Specs.Block("/usr/bin/wget") with { RemotePorts = "443" };
        var allow = Specs.Block("/usr/bin/wget") with { Action = FirewallAction.Allow };
        var inbound = Specs.Block("/usr/bin/wget", direction: FirewallDirection.Inbound);
        var disabled = Specs.Block("/usr/bin/wget") with { Enabled = false };
        var missing = Specs.Block("/opt/nowhere/app");
        var specs = new[]
        {
            Specs.Block("/usr/bin/curl", RuleA) with { Protocol = NetworkProtocol.Tcp },
            Specs.Block("/usr/bin/curl") with { Protocol = NetworkProtocol.Udp },
            scopedAddress,
            scopedPort,
            allow,
            inbound,
            disabled,
            missing,
        };

        var plan = BpfVerdictPlanner.Plan(specs, 7, cgroups, inodes);

        Assert.Equal(1, plan.ExeEntries);
        Assert.Equal(1, plan.CgroupEntries);
        var exe = Assert.Single(plan.Entries, entry => entry.Map == BpfLayout.ExeMap);
        Assert.Equal(BpfLayout.HexString(BpfLayout.ExeKey(8, 2, 51643045)), exe.KeyHex);
        Assert.Equal(BpfLayout.ActionBlock, exe.Value[0]);
        Assert.Equal(BpfLayout.ProtoTcp | BpfLayout.ProtoUdp, exe.Value[1]); // merged, no "other"
        Assert.Equal(RuleA.ToByteArray(), exe.Value[8..]); // first rule's id wins
        var cgroup = Assert.Single(plan.Entries, entry => entry.Map == BpfLayout.CgroupMap);
        Assert.Equal(BpfLayout.HexString(BpfLayout.CgroupKey(93)), cgroup.KeyHex);
        Assert.Contains("/usr/bin/curl", exe.Describe, StringComparison.Ordinal);

        var uncovered = plan.Uncovered.ToDictionary(rule => rule.RuleId, rule => rule.Reason);
        Assert.Contains("address scope", uncovered[scopedAddress.ManagedRuleId], StringComparison.Ordinal);
        Assert.Contains("port scope", uncovered[scopedPort.ManagedRuleId], StringComparison.Ordinal);
        Assert.Contains("allow rules", uncovered[allow.ManagedRuleId], StringComparison.Ordinal);
        Assert.Contains("inbound", uncovered[inbound.ManagedRuleId], StringComparison.Ordinal);
        Assert.Contains("not reachable", uncovered[missing.ManagedRuleId], StringComparison.Ordinal);
        Assert.DoesNotContain(disabled.ManagedRuleId, uncovered.Keys);
        Assert.DoesNotContain(plan.Entries, entry => entry.Describe.Contains("wget", StringComparison.Ordinal)); // never widened
    }

    [Fact]
    public void Probe_degrades_in_order_root_objects_bpftool_btf_bpffs()
    {
        using var temp = new TempDirectory();
        var paths = Paths(temp, createObjects: false);
        var runner = new FakeBpftool(paths.PinDirectory);

        Assert.Contains("not root", BpfCapabilityProbe.Probe(runner, paths, privileged: false).Reason, StringComparison.Ordinal);
        Assert.Contains("not shipped", BpfCapabilityProbe.Probe(runner, paths, privileged: true).Reason, StringComparison.Ordinal);

        paths = Paths(temp, createObjects: true);
        runner.FailPrefixes.Add("bpftool version");
        Assert.Contains("bpftool is not available", BpfCapabilityProbe.Probe(runner, paths, privileged: true).Reason, StringComparison.Ordinal);
        runner.FailPrefixes.Clear();

        var noBtf = paths with { BtfFile = Path.Combine(temp.Path, "no-btf") };
        Assert.Contains("no BTF", BpfCapabilityProbe.Probe(runner, noBtf, privileged: true).Reason, StringComparison.Ordinal);

        var noBpffs = paths with { BpfFs = Path.Combine(temp.Path, "no-bpffs") };
        Assert.Contains("bpffs", BpfCapabilityProbe.Probe(runner, noBpffs, privileged: true).Reason, StringComparison.Ordinal);

        var ok = BpfCapabilityProbe.Probe(runner, paths, privileged: true);
        Assert.True(ok.Usable);
        Assert.Equal("bpftool v7.4.0", ok.BpftoolVersion);
    }

    [Fact]
    public void Event_lines_parse_and_the_monitor_emits_the_flow_pair_with_a_bpf_id()
    {
        var hex = Convert.ToHexStringLower(RuleA.ToByteArray());
        var line = "{\"abi\":1,\"ts\":123,\"pid\":4242,\"cgroup\":93,\"devMajor\":8,\"devMinor\":2,\"ino\":51643045,\"family\":2,\"proto\":6," +
                   "\"daddr\":\"93.184.216.34\",\"dport\":443,\"verdict\":\"block\",\"source\":\"exe\",\"hook\":\"connect\",\"generation\":7,\"ruleId\":\"" + hex + "\"}";
        var flow = BpfEventParser.TryParse(line);
        Assert.NotNull(flow);
        Assert.Equal(4242, flow.Pid);
        Assert.Equal("tcp", flow.ProtocolName);
        Assert.Equal("0.0.0.0", flow.LocalAddress);
        Assert.Equal(RuleA, flow.RuleId);
        Assert.Equal("exe", flow.Source);
        Assert.Null(BpfEventParser.TryParse("{\"abi\":1,\"type\":\"hello\",\"map\":\"/sys/fs/bpf/axiom/maps/axiom_events\"}"));
        Assert.Null(BpfEventParser.TryParse(line.Replace("\"abi\":1", "\"abi\":2", StringComparison.Ordinal)));
        Assert.Null(BpfEventParser.TryParse("not json"));

        var sink = new CollectingSink();
        var monitor = new BpfEventMonitor(new FakeBpfEventSource([line]), pid => pid == 4242 ? "/usr/bin/curl" : null, _ => null, sink, new ManualTimeProvider(new DateTimeOffset(2026, 11, 12, 10, 0, 0, TimeSpan.Zero)));
        monitor.Publish(flow);
        Assert.Equal(2, sink.Lines.Count);
        Assert.Contains("\"type\":\"flow.open\"", sink.Lines[0], StringComparison.Ordinal);
        Assert.Contains("\"id\":\"bpf-1\"", sink.Lines[0], StringComparison.Ordinal);
        Assert.Contains("\"pid\":4242", sink.Lines[0], StringComparison.Ordinal);
        Assert.Contains("\"path\":\"/usr/bin/curl\"", sink.Lines[0], StringComparison.Ordinal);
        Assert.Contains("\"remoteAddress\":\"93.184.216.34\",\"remotePort\":443", sink.Lines[0], StringComparison.Ordinal);
        Assert.Contains("\"verdict\":\"block\",\"ruleId\":\"0f8fad5b-d9cb-469f-a165-70867728950e\"", sink.Lines[0], StringComparison.Ordinal);
        Assert.Contains("\"type\":\"flow.close\",\"id\":\"bpf-1\"", sink.Lines[1], StringComparison.Ordinal);

        // Process already gone: the rule's app path is used.
        var fallback = new BpfEventMonitor(new FakeBpfEventSource([]), _ => null, id => id == RuleA ? (-1, "/usr/bin/curl") : null, sink, TimeProvider.System);
        fallback.Publish(flow);
        Assert.Contains("\"path\":\"/usr/bin/curl\"", sink.Lines[2], StringComparison.Ordinal);
    }

    [Fact]
    public async Task Monitor_run_consumes_the_source_until_it_ends()
    {
        var hex = Convert.ToHexStringLower(RuleA.ToByteArray());
        var sink = new CollectingSink();
        var source = new FakeBpfEventSource(
        [
            "{\"abi\":1,\"type\":\"hello\"}",
            "{\"abi\":1,\"pid\":1,\"family\":10,\"proto\":17,\"daddr\":\"2606:2800:220:1:248:1893:25c8:1946\",\"dport\":53,\"verdict\":\"block\",\"ruleId\":\"" + hex + "\"}",
        ]);
        var monitor = new BpfEventMonitor(source, _ => null, _ => null, sink, TimeProvider.System);
        await monitor.RunAsync(CancellationToken.None);
        Assert.Equal(1, monitor.EventsEmitted);
        Assert.Contains("\"protocol\":\"udp\",\"localAddress\":\"::\"", sink.Lines[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task Engine_loads_pins_attaches_syncs_maps_and_unpins_through_bpftool()
    {
        using var temp = new TempDirectory();
        var paths = Paths(temp, createObjects: true);
        var runner = new FakeBpftool(paths.PinDirectory);
        var fs = new FakeCgroupFs();
        fs.AppPaths["/usr/bin/curl"] = "/usr/bin/curl";
        var cgroups = new AppCgroupManager(fs);
        var inodes = new FakeInodes();
        inodes.Files["/usr/bin/curl"] = new BpfInode(8, 2, 51643045);
        Assert.True(cgroups.TryResolve("/usr/bin/curl", out var curlCgroup, out _));
        inodes.CgroupIds[curlCgroup] = 93;
        var log = new List<string>();
        using var engine = new BpfEngine(runner, paths, inodes, cgroups, null, _ => null, _ => null, new CollectingSink(), privileged: true, TimeProvider.System) { Log = log.Add };

        await engine.StartAsync(CancellationToken.None);

        Assert.True(engine.Active);
        Assert.Contains($"bpftool prog loadall {paths.ObjectFile} {paths.PinDirectory} pinmaps {paths.MapDirectory}", runner.Calls);
        foreach (var (hook, program) in BpfLayout.Programs)
        {
            Assert.Contains($"bpftool cgroup attach {paths.CgroupRoot} {hook} pinned {paths.ProgramPin(program)} multi", runner.Calls);
        }

        var rules = new List<ManagedRule> { Managed(Specs.Block("/usr/bin/curl", RuleA)) };
        await engine.SyncAsync(rules, 5, CancellationToken.None);

        var update = Assert.Single(runner.Calls, call => call.StartsWith($"bpftool map update pinned {paths.MapPin(BpfLayout.ExeMap)} key hex 08 00 00 00 02 00 00 00 a5 02 14 03 00 00 00 00 value hex 02 07 00 00 05 00 00 00", StringComparison.Ordinal));
        Assert.EndsWith(" any", update, StringComparison.Ordinal);
        Assert.Contains(runner.Calls, call => call.StartsWith($"bpftool map update pinned {paths.MapPin(BpfLayout.CgroupMap)} key hex", StringComparison.Ordinal));
        Assert.Equal(2, engine.AppliedEntries.Count);
        Assert.Equal(5, engine.Generation);
        Assert.Contains(log, line => line.Contains("BPF verdicts generation 5: 1 exe, 1 cgroup entries", StringComparison.Ordinal));

        // Rule removed: stale keys are deleted, nothing re-added.
        runner.Calls.Clear();
        await engine.SyncAsync([], 6, CancellationToken.None);
        Assert.Equal(2, runner.Calls.Count(call => call.StartsWith("bpftool map delete pinned", StringComparison.Ordinal)));
        Assert.DoesNotContain(runner.Calls, call => call.StartsWith("bpftool map update", StringComparison.Ordinal));
        Assert.Empty(engine.AppliedEntries);

        await engine.StopAsync();
        Assert.False(engine.Active);
        Assert.Equal("stopped", engine.Status);
        Assert.Equal(BpfLayout.Programs.Count, runner.Calls.Count(call => call.StartsWith($"bpftool cgroup detach {paths.CgroupRoot} ", StringComparison.Ordinal)));
        Assert.False(Directory.Exists(paths.PinDirectory));
        Assert.Contains("stopped", Assert.Single(engine.Limitations), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Engine_rolls_back_when_attach_fails_and_stays_nft_only()
    {
        using var temp = new TempDirectory();
        var paths = Paths(temp, createObjects: true);
        var runner = new FakeBpftool(paths.PinDirectory);
        runner.FailPrefixes.Add("bpftool cgroup attach");
        using var engine = new BpfEngine(runner, paths, new FakeInodes(), new AppCgroupManager(new FakeCgroupFs()), null, _ => null, _ => null, new CollectingSink(), privileged: true, TimeProvider.System);

        await engine.StartAsync(CancellationToken.None);

        Assert.False(engine.Active);
        Assert.Contains("attaching axiom_connect4", engine.Status, StringComparison.Ordinal);
        Assert.Contains("simulated failure", engine.Status, StringComparison.Ordinal);
        Assert.False(Directory.Exists(paths.PinDirectory));
        var limitation = Assert.Single(engine.Limitations);
        Assert.Contains("inactive", limitation, StringComparison.Ordinal);

        runner.Calls.Clear();
        await engine.SyncAsync([Managed(Specs.Block("/usr/bin/curl"))], 3, CancellationToken.None);
        Assert.Empty(runner.Calls); // inactive layer never touches maps
    }

    [Fact]
    public async Task Engine_without_shipped_objects_or_root_never_calls_bpftool_beyond_the_probe()
    {
        using var temp = new TempDirectory();
        var paths = Paths(temp, createObjects: false);
        var runner = new FakeBpftool(paths.PinDirectory);
        using var engine = new BpfEngine(runner, paths, new FakeInodes(), new AppCgroupManager(new FakeCgroupFs()), null, _ => null, _ => null, new CollectingSink(), privileged: true, TimeProvider.System);

        await engine.StartAsync(CancellationToken.None);
        Assert.False(engine.Active);
        Assert.StartsWith("inactive: BPF object not shipped", engine.Status, StringComparison.Ordinal);
        Assert.Empty(runner.Calls);

        using var unprivileged = new BpfEngine(runner, Paths(temp, createObjects: true), new FakeInodes(), new AppCgroupManager(new FakeCgroupFs()), null, _ => null, _ => null, new CollectingSink(), privileged: false, TimeProvider.System);
        await unprivileged.StartAsync(CancellationToken.None);
        Assert.Contains("not root", unprivileged.Status, StringComparison.Ordinal);
        Assert.Empty(runner.Calls);
        await unprivileged.StopAsync();
    }

    [Fact]
    public async Task Adapter_syncs_the_layer_after_every_publish_and_reports_an_inactive_layer()
    {
        using var temp = new TempDirectory();
        var fs = new FakeCgroupFs();
        fs.AppPaths["/usr/bin/curl"] = "/usr/bin/curl";
        var nft = new FakeNftRunner();
        var layer = new RecordingLayer();
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 11, 12, 10, 0, 0, TimeSpan.Zero));
        using var adapter = new NftFirewallPolicyAdapter(new NftEnginePaths(Path.Combine(temp.Path, "filter")), new NftTable(nft), new AppCgroupManager(fs), new CollectingSink(), () => true, time)
        {
            VerdictLayer = layer,
        };

        var result = await adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        Assert.True(result.Success);
        var sync = Assert.Single(layer.Syncs);
        Assert.Equal((1, 1L), sync);

        await adapter.RemoveOwnedRuleAsync(RuleA, CancellationToken.None);
        Assert.Equal((0, 2L), layer.Syncs[^1]);

        layer.Syncs.Clear();
        await adapter.ResyncLayerAsync(CancellationToken.None);
        Assert.Equal((0, 2L), Assert.Single(layer.Syncs));

        var capabilities = await adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FirewallCapabilityStatus.Available, capabilities.Status);
        Assert.Contains("Connect-time BPF layer inactive: test", capabilities.Reason, StringComparison.Ordinal);

        layer.Active = true;
        capabilities = await adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Null(capabilities.Reason);

        // A refused batch never syncs the layer.
        nft.ApplyError = "Error: syntax error";
        layer.Syncs.Clear();
        await adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl"), CancellationToken.None);
        Assert.Empty(layer.Syncs);
    }

    [Fact]
    public async Task Supervisor_starts_the_layer_after_the_first_publish_and_stops_it_before_teardown()
    {
        using var temp = new TempDirectory();
        var fs = new FakeCgroupFs();
        var nft = new FakeNftRunner();
        var layer = new RecordingLayer { Active = true };
        var log = new List<string>();
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 11, 12, 10, 0, 0, TimeSpan.Zero));
        using var adapter = new NftFirewallPolicyAdapter(new NftEnginePaths(Path.Combine(temp.Path, "filter")), new NftTable(nft), new AppCgroupManager(fs), new CollectingSink(), () => true, time)
        {
            VerdictLayer = layer,
        };
        var supervisor = new NftEnforcementSupervisor(adapter, new NftTable(nft), null, layer, log.Add, time);

        using var cts = new CancellationTokenSource();
        var run = supervisor.RunAsync(cts.Token);
        Assert.True(SpinWait.SpinUntil(() => layer.Started && layer.Syncs.Count >= 2, TimeSpan.FromSeconds(5)));
        Assert.False(layer.Stopped);
        Assert.Equal(1, supervisor.StartGeneration);
        Assert.Equal((0, 1L), layer.Syncs[0]); // publish at start
        Assert.Equal((0, 1L), layer.Syncs[1]); // resync once attached

        await cts.CancelAsync();
        await run;
        Assert.True(layer.Stopped);
        Assert.Null(nft.TableGeneration);
    }

    [Fact]
    public void Unit_grants_bpf_capabilities_and_the_bpffs_pin_directory()
    {
        var unit = SystemdUnit.Build("/usr/libexec/axiom/axiomd", "/var/lib/axiom", "/run/axiom");
        Assert.Contains("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN", unit, StringComparison.Ordinal);
        Assert.Contains(" CAP_BPF CAP_PERFMON", unit, StringComparison.Ordinal);
        Assert.Contains("ReadWritePaths=/var/lib/axiom /run/axiom /sys/fs/cgroup /sys/fs/bpf ", unit, StringComparison.Ordinal);
        Assert.Contains("ProtectSystem=strict", unit, StringComparison.Ordinal);
    }

    [Fact]
    public void Doctor_warns_without_btf_or_shipped_object_and_never_fails_for_the_bpf_layer()
    {
        using var temp = new TempDirectory();
        var image = Path.Combine(temp.Path, "image");
        Directory.CreateDirectory(image);
        var btf = Path.Combine(temp.Path, "vmlinux");
        File.WriteAllText(btf, string.Empty);
        var targets = new LinuxDoctorTargets(
            Path.Combine(temp.Path, "axiomd.service"),
            image,
            Path.Combine(temp.Path, "data"),
            Path.Combine(temp.Path, "axiom.sock"),
            Path.Combine(temp.Path, "backup.json"),
            Path.Combine(temp.Path, "protection.json"),
            Path.Combine(temp.Path, "missing-btf"),
            Path.Combine(temp.Path, "pins"));
        var runner = new FakeBpftool(Path.Combine(temp.Path, "pins"));

        var noBtf = new LinuxDoctor(runner, targets, isRoot: false).Collect().Single(check => check.Name == "bpf layer");
        Assert.Equal(DoctorCheck.Warn, noBtf.Status);
        Assert.Contains("without BTF", noBtf.Detail, StringComparison.Ordinal);

        var noObject = new LinuxDoctor(runner, targets with { BtfFile = btf }, isRoot: false).Collect().Single(check => check.Name == "bpf layer");
        Assert.Equal(DoctorCheck.Warn, noObject.Status);
        Assert.Contains("not shipped", noObject.Detail, StringComparison.Ordinal);

        Directory.CreateDirectory(Path.Combine(image, "bpf"));
        File.WriteAllText(Path.Combine(image, "bpf", BpfEnginePaths.ObjectFileName), string.Empty);
        var unprivileged = new LinuxDoctor(runner, targets with { BtfFile = btf }, isRoot: false).Collect().Single(check => check.Name == "bpf layer");
        Assert.Equal(DoctorCheck.Skip, unprivileged.Status);

        runner.FailPrefixes.Add("bpftool version");
        var noTool = new LinuxDoctor(runner, targets with { BtfFile = btf }, isRoot: true).Collect().Single(check => check.Name == "bpf layer");
        Assert.Equal(DoctorCheck.Warn, noTool.Status);
        Assert.NotEqual(DoctorCheck.Fail, noTool.Status);
    }

    private static ManagedRule Managed(RuleSpec spec) => new()
    {
        ManagedRuleId = spec.ManagedRuleId,
        OsRuleName = "Axiom-" + spec.ManagedRuleId.ToString("N"),
        OwnershipGroup = OwnedRuleOwnership.GroupName,
        Spec = spec,
        State = RuleState.Applied,
    };

    private static BpfEnginePaths Paths(TempDirectory temp, bool createObjects)
    {
        var bpf = Path.Combine(temp.Path, "image", "bpf");
        var bpffs = Path.Combine(temp.Path, "bpffs");
        Directory.CreateDirectory(bpffs);
        var btf = Path.Combine(temp.Path, "vmlinux");
        File.WriteAllText(btf, string.Empty);
        if (createObjects)
        {
            Directory.CreateDirectory(bpf);
            File.WriteAllText(Path.Combine(bpf, BpfEnginePaths.ObjectFileName), string.Empty);
            File.WriteAllText(Path.Combine(bpf, BpfEnginePaths.EventsHelperName), string.Empty);
        }

        return new BpfEnginePaths(
            Path.Combine(bpf, BpfEnginePaths.ObjectFileName),
            Path.Combine(bpf, BpfEnginePaths.EventsHelperName),
            Path.Combine(bpffs, "axiom"),
            Path.Combine(temp.Path, "cgroup"),
            btf,
            bpffs);
    }

    private sealed class FakeBpfEventSource(IReadOnlyList<string> lines) : IBpfEventSource
    {
        public async IAsyncEnumerable<string> ReadLinesAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
        {
            foreach (var line in lines)
            {
                ct.ThrowIfCancellationRequested();
                await Task.Yield();
                yield return line;
            }
        }
    }
}
