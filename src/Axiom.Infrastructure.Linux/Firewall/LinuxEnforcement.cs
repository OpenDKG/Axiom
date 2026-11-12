// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.Versioning;
using Axiom.Infrastructure.Linux.Bpf;
using Axiom.Infrastructure.Linux.Nft;
using Axiom.Infrastructure.Unix.Filter;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Firewall;

/// <summary>
/// In-process replacement for the macOS filter socket: the nftables engine emits the same NDJSON
/// lines the AxiomFilter extension would send, and this sink parses them straight into
/// <see cref="FilterEventServer.Accept"/> so <c>FilterStatus</c> (hello/rules reports) and
/// <c>FlowTable</c> (blocked flows) are populated exactly as on macOS. Lines that do not parse are
/// counted on the server like garbage from a socket client.
/// </summary>
[UnsupportedOSPlatform("windows")]
public sealed class FilterEventPipe : IFilterEventSink
{
    private readonly FilterEventServer _server;

    private long _rejected;

    public FilterEventPipe(FilterEventServer server)
    {
        _server = server ?? throw new ArgumentNullException(nameof(server));
    }

    public long RejectedLines => Interlocked.Read(ref _rejected);

    public void Emit(string ndjsonLine)
    {
        var flowEvent = FlowEventParser.TryParse(ndjsonLine);
        if (flowEvent is null)
        {
            Interlocked.Increment(ref _rejected);
            return;
        }

        _server.Accept(flowEvent);
    }
}

/// <summary>Sink for contexts without a daemon (recovery command, doctor): events are dropped.</summary>
public sealed class NullFilterEventSink : IFilterEventSink
{
    public static NullFilterEventSink Instance { get; } = new();

    public void Emit(string ndjsonLine)
    {
    }
}

/// <summary>Production construction of the engine for the daemon paths (docs/LINUX_ENFORCEMENT.md §6).</summary>
[SupportedOSPlatform("linux")]
public static class LinuxEnforcement
{
    public static NftEnginePaths EnginePaths(LinuxServicePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        return new NftEnginePaths(paths.FilterDirectory);
    }

    public static NftFirewallPolicyAdapter CreateAdapter(LinuxServicePaths paths, IFilterEventSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        return new NftFirewallPolicyAdapter(EnginePaths(paths), new NftTable(new NftProcessRunner()), new AppCgroupManager(new ProcCgroupFs()), sink);
    }

    public static NftTraceMonitor CreateTraceMonitor(NftFirewallPolicyAdapter adapter, IFilterEventSink sink)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(sink);
        return new NftTraceMonitor(new NftTraceProcessSource(), new ProcNetSocketLookup(), adapter.DescribeRuleApp, sink, TimeProvider.System);
    }

    /// <summary>
    /// The connect-time BPF layer over the shipped objects (<c>bpf/</c> next to the daemon), wired
    /// as the adapter's <see cref="NftFirewallPolicyAdapter.VerdictLayer"/> so every publish syncs
    /// the verdict maps. Inactive (nft-only) when the probe says no; see docs/LINUX_EBPF.md §6.
    /// </summary>
    public static BpfEngine CreateBpfEngine(NftFirewallPolicyAdapter adapter, IFilterEventSink sink)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(sink);
        var paths = BpfEnginePaths.Default;
        var fs = new ProcCgroupFs();
        var engine = new BpfEngine(
            ProcessRunner.Instance,
            paths,
            new StatInodeReader(ProcessRunner.Instance),
            adapter.Cgroups,
            () => new BpfEventProcessSource(paths.EventsHelper, paths.MapPin(BpfLayout.EventsMap)),
            fs.ReadProcessExe,
            adapter.DescribeRuleApp,
            sink,
            Environment.IsPrivilegedProcess,
            TimeProvider.System);
        adapter.VerdictLayer = engine;
        return engine;
    }

    public static NftEnforcementSupervisor CreateSupervisor(NftFirewallPolicyAdapter adapter, IFilterEventSink sink, Action<string> log, BpfEngine? bpf = null)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        if (bpf is not null)
        {
            bpf.Log = log;
        }

        return new NftEnforcementSupervisor(
            adapter,
            new NftTable(new NftProcessRunner()),
            () => CreateTraceMonitor(adapter, sink),
            bpf,
            log,
            TimeProvider.System);
    }
}
