// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Bpf;
using Axiom.Infrastructure.Linux.Nft;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

/// <summary>
/// PR #276 review (brxtrac), finding 4: when <c>bpftool cgroup show</c> cannot be read (non-zero
/// exit, or exit 0 with output that is not the expected JSON) the attachment state is unknown. Unknown
/// is never "not attached": the daemon keeps its pins, loads no second program set, keeps a requested
/// removal pending and reports the state as unknown. A removal is confirmed only after a readable zero.
/// </summary>
public sealed class BpfUnconfirmedAttachmentTests
{
    private static readonly Guid RuleA = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");

    public enum Fault
    {
        NonJsonExitZero,
        ExitOne,
    }

    private static void Break(BpfEffectiveStateTests.Harness h, Fault fault)
    {
        if (fault == Fault.NonJsonExitZero)
        {
            h.Bpftool.CgroupShowOutput = "shim: <<not json>> {";
        }
        else
        {
            h.Bpftool.FailPrefixes.Add("bpftool -j cgroup show");
        }
    }

    private static void Repair(BpfEffectiveStateTests.Harness h)
    {
        h.Bpftool.CgroupShowOutput = null;
        h.Bpftool.FailPrefixes.Remove("bpftool -j cgroup show");
    }

    private static int Loads(FakeBpftool bpftool) => bpftool.Calls.Count(call => call.StartsWith("bpftool prog loadall", StringComparison.Ordinal));

    private static NftEnforcementSupervisor Supervisor(BpfEffectiveStateTests.Harness h) =>
        new(h.Adapter, new NftTable(h.Nft), null, h.Engine, h.Log.Add, h.Time);

    [Theory]
    [InlineData("shim: <<not json>> {")]
    [InlineData("{}")]
    [InlineData("[")]
    [InlineData("[{\"id\":\"12\",\"attach_type\":\"cgroup_inet4_connect\",\"name\":\"axiom_connect4\"}]")]
    [InlineData("[{\"id\":-3,\"attach_type\":\"cgroup_inet4_connect\",\"name\":\"axiom_connect4\"}]")]
    [InlineData("[{\"id\":0,\"attach_type\":\"cgroup_inet4_connect\",\"name\":\"axiom_connect4\"}]")]
    [InlineData("[{\"id\":1.5,\"attach_type\":\"cgroup_inet4_connect\",\"name\":\"axiom_connect4\"}]")]
    [InlineData("[{\"attach_type\":\"cgroup_inet4_connect\",\"name\":\"axiom_connect4\"}]")]
    [InlineData("[{\"id\":12,\"attach_type\":\"cgroup_inet4_connect\",\"name\":7}]")]
    [InlineData("[{\"id\":12,\"attach_type\":\"cgroup_inet4_connect\"}]")]
    [InlineData("[{\"id\":12,\"attach_type\":\"cgroup_inet4_connect\",\"name\":\"axiom_connect4\"},17]")]
    public void Unreadable_cgroup_show_output_parses_as_unknown_not_as_nothing_attached(string output)
    {
        Assert.Null(BpfMapDump.ParseAttached(output));
    }

    [Fact]
    public void Readable_cgroup_show_output_parses_as_a_list_and_an_empty_array_as_zero()
    {
        Assert.Empty(BpfMapDump.ParseAttached("[]")!);

        // bpftool v7.7.0 `-j cgroup show` on a cgroup with no programs prints a bare newline, exit 0.
        Assert.Empty(BpfMapDump.ParseAttached("\n")!);
        Assert.Empty(BpfMapDump.ParseAttached(string.Empty)!);
        var attached = BpfMapDump.ParseAttached("[{\"id\":12,\"attach_type\":\"cgroup_inet4_connect\",\"attach_flags\":\"multi\",\"name\":\"axiom_connect4\"},{\"id\":13,\"attach_type\":\"cgroup_inet6_connect\",\"name\":\"\"}]");
        Assert.NotNull(attached);
        Assert.Equal(2, attached!.Count);
        Assert.Equal((12L, "axiom_connect4", "cgroup_inet4_connect"), attached[0]);
    }

    [Theory]
    [InlineData(Fault.NonJsonExitZero)]
    [InlineData(Fault.ExitOne)]
    public async Task Watch_ticks_with_unreadable_attachment_state_keep_pins_and_load_no_second_set(Fault fault)
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.AttachAsync();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        var supervisor = Supervisor(h);
        Assert.Equal(4, h.Bpftool.Attached.Count);
        Assert.Equal(1, Loads(h.Bpftool));

        Break(h, fault);
        for (var tick = 0; tick < 4; tick++)
        {
            await supervisor.WatchOnceAsync(CancellationToken.None);
        }

        Assert.Equal(1, Loads(h.Bpftool));
        Assert.Equal(4, h.Bpftool.Attached.Count);
        Assert.True(Directory.Exists(h.BpfPaths.PinDirectory), "pins must be kept while attachment cannot be confirmed");
        Assert.True(File.Exists(h.BpfPaths.MapPin(BpfLayout.ExeMap)));
        Assert.False(h.Engine.Neutralised);
        Assert.True(h.Engine.AttachmentUnknown);
        Assert.DoesNotContain(h.Log, line => line.Contains("detached by another tool", StringComparison.Ordinal));
        Assert.DoesNotContain(h.Log, line => line.Contains("reconciled orphaned state", StringComparison.Ordinal));

        var capability = await h.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        var layer = capability.ConnectTimeLayer!;
        Assert.Equal("unknown", layer.State);
        Assert.False(layer.Healthy);
        Assert.True(layer.Attached, "unknown must not be reported as attached:false");
        Assert.Empty(layer.ConnectTimeProvenRules);
        Assert.Contains("cannot confirm", layer.Status, StringComparison.Ordinal);
        Assert.NotEqual(FirewallCapabilityStatus.Available, capability.Status);
        Assert.Contains("cannot confirm", capability.Reason ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain("detached by another tool", capability.Reason ?? string.Empty, StringComparison.Ordinal);

        // The fault clears: the next tick reads a confirmed 4/4 and the layer is active again, still one set.
        Repair(h);
        await supervisor.WatchOnceAsync(CancellationToken.None);
        Assert.False(h.Engine.AttachmentUnknown);
        Assert.True(h.Engine.Active);
        Assert.Equal(1, Loads(h.Bpftool));
        Assert.Equal(4, h.Bpftool.Attached.Count);
        Assert.Equal("active", (await h.Adapter.GetCapabilitiesAsync(CancellationToken.None)).ConnectTimeLayer!.State);
    }

    [Theory]
    [InlineData(Fault.NonJsonExitZero)]
    [InlineData(Fault.ExitOne)]
    public async Task Removal_while_attachment_is_unknown_stays_pending_until_a_readable_zero(Fault fault)
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.AttachAsync();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        var supervisor = Supervisor(h);
        Break(h, fault);
        h.Bpftool.FailPrefixes.Add("bpftool map delete");
        h.Bpftool.FailPrefixes.Add("bpftool cgroup detach");

        var removal = await h.Adapter.RemoveOwnedRuleAsync(RuleA, CancellationToken.None);

        Assert.False(removal.Success);
        Assert.Equal(RuleState.Pending, removal.State);
        Assert.Null(removal.VerifiedUtc);
        Assert.NotNull(removal.ErrorCode);
        Assert.DoesNotContain("nothing of this rule enforces now", removal.ErrorMessage ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain("cannot block", removal.ErrorMessage ?? string.Empty, StringComparison.Ordinal);
        Assert.Contains(h.Adapter.PendingRemovals, pending => pending.RuleId == RuleA);
        Assert.True(Directory.Exists(h.BpfPaths.PinDirectory));
        Assert.Equal(4, h.Bpftool.Attached.Count);
        Assert.False(h.Engine.Neutralised);

        await supervisor.WatchOnceAsync(CancellationToken.None);
        await supervisor.WatchOnceAsync(CancellationToken.None);
        Assert.Equal(1, Loads(h.Bpftool));
        Assert.Contains(h.Adapter.PendingRemovals, pending => pending.RuleId == RuleA);
        var layer = (await h.Adapter.GetCapabilitiesAsync(CancellationToken.None)).ConnectTimeLayer!;
        Assert.Contains(RuleA, layer.PendingRemovals);
        Assert.Equal("unknown", layer.State);

        // bpftool works again: the removal is confirmed only by a readable sync, then cleared.
        Repair(h);
        h.Bpftool.FailPrefixes.Remove("bpftool map delete");
        h.Bpftool.FailPrefixes.Remove("bpftool cgroup detach");
        await supervisor.WatchOnceAsync(CancellationToken.None);
        Assert.Empty(h.Adapter.PendingRemovals);
        Assert.Empty(h.Bpftool.Map(h.BpfPaths.MapPin(BpfLayout.ExeMap)));
        Assert.Equal(4, h.Bpftool.Attached.Count);
    }

    [Fact]
    public async Task Removal_with_unreadable_attachment_state_is_not_verified_even_when_the_map_delete_succeeded()
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.AttachAsync();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        Break(h, Fault.NonJsonExitZero);

        var removal = await h.Adapter.RemoveOwnedRuleAsync(RuleA, CancellationToken.None);

        Assert.False(removal.Success && removal.VerifiedUtc is not null, "a removal must not be verified while attachment cannot be read");
        Assert.Equal(RuleState.Pending, removal.State);
        Assert.Contains(h.Adapter.PendingRemovals, pending => pending.RuleId == RuleA);
    }

    [Theory]
    [InlineData(Fault.NonJsonExitZero)]
    [InlineData(Fault.ExitOne)]
    public async Task Restart_with_unreadable_attachment_state_keeps_the_old_pins_and_loads_no_second_set(Fault fault)
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.AttachAsync();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        Break(h, fault);
        h.Bpftool.FailPrefixes.Add("bpftool cgroup detach");

        // The previous daemon was killed; a new engine starts against the same kernel state.
        using var next = new BpfEngine(h.Bpftool, h.BpfPaths, h.Inodes, new AppCgroupManager(h.Fs), null, _ => null, _ => null, new CollectingSink(), privileged: true, h.Time) { Log = h.Log.Add };
        await next.StartAsync(CancellationToken.None);
        await next.StartAsync(CancellationToken.None);

        Assert.Equal(1, Loads(h.Bpftool));
        Assert.Equal(4, h.Bpftool.Attached.Count);
        Assert.True(File.Exists(h.BpfPaths.ProgramPin(BpfLayout.Programs[0].Program)));
        Assert.False(next.Active);
        Assert.True(next.AttachmentUnknown);
        Assert.StartsWith("unknown", next.Status, StringComparison.Ordinal);
        Assert.DoesNotContain(h.Log, line => line.Contains("reconciled orphaned state", StringComparison.Ordinal) && line.Contains("pins", StringComparison.Ordinal));

        Repair(h);
        h.Bpftool.FailPrefixes.Remove("bpftool cgroup detach");
        await next.StartAsync(CancellationToken.None);

        // Make-before-break (docs/LINUX_EBPF.md §11): the new set is attached next to the old one and
        // only the first sync (populated + read back) retires the old set.
        Assert.True(next.Pending);
        Assert.Equal(8, h.Bpftool.Attached.Count);
        await next.SyncAsync([], 1, CancellationToken.None);
        Assert.True(next.Active);
        Assert.False(next.AttachmentUnknown);
        Assert.Equal(2, Loads(h.Bpftool));
        Assert.Equal(4, h.Bpftool.Attached.Count);
    }

    [Fact]
    public async Task Failed_detach_with_unreadable_attachment_state_is_not_reported_as_neutralised()
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.AttachAsync();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        Break(h, Fault.ExitOne);
        h.Bpftool.FailPrefixes.Add("bpftool map delete");
        h.Bpftool.FailPrefixes.Add("bpftool cgroup detach");

        var sync = await h.Engine.SyncAsync([], 9, CancellationToken.None);

        Assert.False(sync.Neutralised);
        Assert.True(sync.AttachmentUnknown);
        Assert.True(sync.StaleEntriesCanBlock);
        Assert.False(sync.Verified);
        Assert.True(Directory.Exists(h.BpfPaths.PinDirectory));
        Assert.DoesNotContain(h.Log, line => line.Contains("layer neutralised", StringComparison.Ordinal));
    }
}
