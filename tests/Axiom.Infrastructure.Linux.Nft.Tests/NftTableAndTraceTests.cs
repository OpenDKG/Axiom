// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Text.Json;
using Axiom.Infrastructure.Linux.Nft;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

public sealed class NftTableAndTraceTests
{
    private const string ListJson = """
        {"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": "axiom", "handle": 12, "comment": "axiom generation 42"}},
        {"chain": {"family": "inet", "table": "axiom", "name": "axiom_out", "handle": 1, "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}},
        {"rule": {"family": "inet", "table": "axiom", "chain": "axiom_out", "handle": 3, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": {"prefix": {"addr": "127.0.0.0", "len": 8}}}}, {"accept": null}]}},
        {"rule": {"family": "inet", "table": "axiom", "chain": "axiom_out", "handle": 5, "comment": "axiom:0f8fad5b-d9cb-469f-a165-70867728950e:1", "expr": [{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}}, {"match": {"op": "==", "left": {"socket": {"key": "cgroupv2", "level": 2}}, "right": 4648572}}, {"counter": {"packets": 2, "bytes": 120}}, {"mangle": {"key": {"meta": {"key": "nftrace"}}, "value": 1}}, {"reject": {"type": "tcp reset"}}]}},
        {"rule": {"family": "inet", "table": "axiom", "chain": "axiom_out", "handle": 6, "comment": "axiom:0f8fad5b-d9cb-469f-a165-70867728950e:2", "expr": [{"counter": {"packets": 0, "bytes": 0}}, {"drop": null}]}},
        {"rule": {"family": "inet", "table": "axiom", "chain": "axiom_in", "handle": 9, "comment": "not ours", "expr": [{"counter": {"packets": 7, "bytes": 7}}, {"drop": null}]}}]}
        """;

    [Fact]
    public void Generation_and_counters_come_from_the_json_listing()
    {
        Assert.Equal(42, NftTable.ParseGeneration(ListJson));
        Assert.Null(NftTable.ParseGeneration(null));
        Assert.Null(NftTable.ParseGeneration("""{"nftables":[{"table":{"family":"inet","name":"axiom"}}]}"""));
        Assert.Null(NftTable.ParseGeneration("not json"));

        var counters = NftTable.ParseCounters(ListJson);

        Assert.Equal(2, counters.Count);
        Assert.Equal(new NftRuleCounter(Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"), 1, 5, 2, 120, "axiom_out"), counters[0]);
        Assert.Equal(new NftRuleCounter(Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"), 2, 6, 0, 0, "axiom_out"), counters[1]);
    }

    [Fact]
    public async Task Apply_pipes_the_script_and_reports_nft_errors()
    {
        var runner = new FakeNftRunner();
        var table = new NftTable(runner);

        var ok = await table.ApplyAsync("add table inet axiom\ndelete table inet axiom\ntable inet axiom {\n\tcomment \"axiom generation 3\"\n}\n", CancellationToken.None);
        Assert.True(ok.Success);
        Assert.Equal(["-f", "-"], runner.Calls[0].Args);
        Assert.Equal(3, await table.ReadGenerationAsync(CancellationToken.None));

        runner.ApplyError = "/dev/stdin:5:3-3: Error: syntax error, unexpected '}'";
        var failed = await table.ApplyAsync("bad", CancellationToken.None);
        Assert.False(failed.Success);
        Assert.Contains("syntax error", failed.Error, StringComparison.Ordinal);

        Assert.True((await table.DeleteAsync(CancellationToken.None)).Success);
        Assert.Null(await table.ReadGenerationAsync(CancellationToken.None));
    }

    [Fact]
    public void Trace_lines_are_joined_by_id_into_block_events_with_rule_ids()
    {
        var parser = new NftTraceParser();

        Assert.Null(parser.Feed("trace id 7a4ab5a1 inet axiom axiom_out packet: oif \"enp3s0\" ip saddr 192.168.1.20 ip daddr 93.184.216.34 ip dscp cs0 ip ecn not-ect ip ttl 64 ip id 0 ip protocol tcp ip length 60 tcp sport 51234 tcp dport 80 tcp flags == syn tcp window 64240"));
        Assert.Null(parser.Feed("trace id 00000001 inet other chain packet: ip saddr 1.1.1.1"));
        var blocked = parser.Feed("trace id 7a4ab5a1 inet axiom axiom_out rule meta l4proto tcp socket cgroupv2 level 2 \"axiom.slice/a-0011\" counter packets 1 bytes 60 meta nftrace set 1 reject with tcp reset comment \"axiom:0f8fad5b-d9cb-469f-a165-70867728950e:1\" (verdict drop)");

        Assert.NotNull(blocked);
        Assert.Equal("7a4ab5a1", blocked.TraceId);
        Assert.Equal("tcp", blocked.Protocol);
        Assert.Equal("192.168.1.20", blocked.LocalAddress);
        Assert.Equal(51234, blocked.LocalPort);
        Assert.Equal("93.184.216.34", blocked.RemoteAddress);
        Assert.Equal(80, blocked.RemotePort);
        Assert.Equal("block", blocked.Verdict);
        Assert.Equal(Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"), blocked.RuleId);
        Assert.Null(parser.Feed("trace id 7a4ab5a1 inet axiom axiom_out verdict drop"));
    }

    [Fact]
    public void Inbound_traces_swap_local_and_remote_and_ipv6_udp_is_read()
    {
        var parser = new NftTraceParser();
        parser.Feed("trace id 0a0b inet axiom axiom_in packet: iif \"enp3s0\" ip6 saddr 2001:db8::9 ip6 daddr 2001:db8::1 ip6 nexthdr udp udp sport 5353 udp dport 53");
        var blocked = parser.Feed("trace id 0a0b inet axiom axiom_in rule meta l4proto udp socket cgroupv2 level 2 \"axiom.slice/a-1\" counter packets 1 bytes 90 meta nftrace set 1 drop comment \"axiom:7c9e6679-7425-40de-944b-e07fc1f90ae7:2\" (verdict drop)");

        Assert.NotNull(blocked);
        Assert.Equal("udp", blocked.Protocol);
        Assert.Equal("2001:db8::1", blocked.LocalAddress);
        Assert.Equal(53, blocked.LocalPort);
        Assert.Equal("2001:db8::9", blocked.RemoteAddress);
        Assert.Equal(5353, blocked.RemotePort);
        Assert.Equal("axiom_in", blocked.Chain);
    }

    [Fact]
    public void Monitor_emits_flow_open_and_close_in_the_filter_contract()
    {
        var sink = new CollectingSink();
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 11, 12, 10, 0, 0, TimeSpan.Zero));
        var ruleId = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");
        var monitor = new NftTraceMonitor(
            new NoSource(),
            new StaticLookup(null),
            id => id == ruleId ? (4242, "/usr/bin/curl") : null,
            sink,
            time);

        monitor.Publish(new NftTraceEvent("7a4ab5a1", "axiom_out", "tcp", "192.168.1.20", 51234, "93.184.216.34", 80, "block", ruleId));

        Assert.Equal(2, sink.Lines.Count);
        using var open = JsonDocument.Parse(sink.Lines[0]);
        var root = open.RootElement;
        Assert.Equal("flow.open", root.GetProperty("type").GetString());
        Assert.Equal("nft-7a4ab5a1-1", root.GetProperty("id").GetString());
        Assert.Equal("2026-11-12T10:00:00.000Z", root.GetProperty("ts").GetString());
        Assert.Equal(4242, root.GetProperty("pid").GetInt32());
        Assert.Equal("/usr/bin/curl", root.GetProperty("path").GetString());
        Assert.Equal("outbound", root.GetProperty("direction").GetString());
        Assert.Equal("tcp", root.GetProperty("protocol").GetString());
        Assert.Equal("192.168.1.20", root.GetProperty("localAddress").GetString());
        Assert.Equal(51234, root.GetProperty("localPort").GetInt32());
        Assert.Equal("93.184.216.34", root.GetProperty("remoteAddress").GetString());
        Assert.Equal(80, root.GetProperty("remotePort").GetInt32());
        Assert.Equal("block", root.GetProperty("verdict").GetString());
        Assert.Equal("0f8fad5b-d9cb-469f-a165-70867728950e", root.GetProperty("ruleId").GetString());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("responsiblePid").ValueKind);
        using var close = JsonDocument.Parse(sink.Lines[1]);
        Assert.Equal("flow.close", close.RootElement.GetProperty("type").GetString());
        Assert.Equal("nft-7a4ab5a1-1", close.RootElement.GetProperty("id").GetString());
        Assert.Equal(0, close.RootElement.GetProperty("bytesIn").GetInt64());

        var socketOwner = new NftTraceMonitor(new NoSource(), new StaticLookup(new SocketOwner(77, "/usr/bin/wget")), _ => null, sink, time);
        socketOwner.Publish(new NftTraceEvent("b", "axiom_in", "udp", "::1", 53, "::2", 5353, "block", null));
        using var inbound = JsonDocument.Parse(sink.Lines[2]);
        Assert.Equal(77, inbound.RootElement.GetProperty("pid").GetInt32());
        Assert.Equal("inbound", inbound.RootElement.GetProperty("direction").GetString());
        Assert.Equal(JsonValueKind.Null, inbound.RootElement.GetProperty("ruleId").ValueKind);
    }

    [Fact]
    public void Hello_and_rules_events_match_the_contract()
    {
        var now = new DateTimeOffset(2026, 11, 12, 10, 0, 0, 500, TimeSpan.Zero);
        using var hello = JsonDocument.Parse(FilterEventFormatter.Hello(5, 0, now));
        Assert.Equal("filter.hello", hello.RootElement.GetProperty("type").GetString());
        Assert.Equal("nft-1", hello.RootElement.GetProperty("version").GetString());
        Assert.Equal(5, hello.RootElement.GetProperty("generation").GetInt64());
        Assert.Equal("2026-11-12T10:00:00.500Z", hello.RootElement.GetProperty("ts").GetString());

        var id = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");
        using var rules = JsonDocument.Parse(FilterEventFormatter.Rules(5, 3, [new NftRejectedRule(id, "invalid address 'x'")], null, 0, now));
        Assert.Equal("filter.rules", rules.RootElement.GetProperty("type").GetString());
        Assert.Equal(3, rules.RootElement.GetProperty("applied").GetInt32());
        var rejected = rules.RootElement.GetProperty("rejected")[0];
        Assert.Equal("0f8fad5b-d9cb-469f-a165-70867728950e", rejected.GetProperty("id").GetString());
        Assert.Equal("invalid address 'x'", rejected.GetProperty("reason").GetString());
        Assert.Equal(JsonValueKind.Null, rules.RootElement.GetProperty("error").ValueKind);

        using var failed = JsonDocument.Parse(FilterEventFormatter.Rules(4, 2, [], "nft: syntax error", 0, now));
        Assert.Equal("nft: syntax error", failed.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public void Proc_net_rows_decode_little_endian_hex_endpoints()
    {
        Assert.True(ProcNetSocketLookup.TryParseProcNetLine("   1: 0100007F:25E4 00000000:0000 0A 00000000:0000000C 00:00000000 00000000  1000        0 13230293 13 0000000000000000 100 0 0 10 0", out var v4, out var port, out var inode));
        Assert.Equal(IPAddress.Loopback, v4);
        Assert.Equal(0x25E4, port);
        Assert.Equal(13230293, inode);

        Assert.True(ProcNetSocketLookup.TryParseProcNetLine("   0: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234 1 0000000000000000 100 0 0 10 0", out var v6, out var port6, out _));
        Assert.Equal(IPAddress.IPv6Loopback, v6);
        Assert.Equal(53, port6);

        Assert.False(ProcNetSocketLookup.TryParseProcNetLine("  sl  local_address rem_address   st", out _, out _, out _));
    }

    private sealed class NoSource : INftTraceSource
    {
        public async IAsyncEnumerable<string> ReadLinesAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
        {
            await Task.CompletedTask.ConfigureAwait(false);
            yield break;
        }
    }

    private sealed class StaticLookup(SocketOwner? owner) : ISocketOwnerLookup
    {
        public SocketOwner? FindOwner(string protocol, string localAddress, int localPort) => owner;
    }
}
