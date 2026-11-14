// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Infrastructure.MacOS.Monitoring;
using Axiom.Infrastructure.MacOS.ProcessIdentity;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class FlowEventTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);

    private const string OpenCurl =
        "{\"type\":\"flow.open\",\"id\":\"f1\",\"ts\":\"2026-11-10T12:00:00Z\",\"pid\":4242," +
        "\"path\":\"/usr/bin/curl\",\"direction\":\"outbound\",\"protocol\":\"tcp\"," +
        "\"localAddress\":\"192.168.64.5\",\"localPort\":50123,\"remoteAddress\":\"93.184.216.34\"," +
        "\"remotePort\":443,\"remoteHost\":\"example.com\",\"verdict\":\"allow\"}";

    [Fact]
    public void ParsesContractFlowOpen()
    {
        var parsed = FlowEventParser.TryParse(OpenCurl);

        Assert.NotNull(parsed);
        Assert.Equal(FlowEventType.Open, parsed.Type);
        Assert.Equal("f1", parsed.Id);
        Assert.Equal(4242, parsed.ProcessId);
        Assert.Equal("/usr/bin/curl", parsed.Path);
        Assert.Equal(443, parsed.RemotePort);
        Assert.Equal("example.com", parsed.RemoteHost);
        Assert.Equal(Start, parsed.Timestamp);
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("[1,2,3]")]
    [InlineData("{\"type\":\"flow.unknown\",\"id\":\"x\"}")]
    [InlineData("{\"type\":\"flow.open\"}")]
    [InlineData("{\"type\":42,\"id\":\"x\"}")]
    [InlineData("{\"type\":\"flow.open\",\"id\":\"x\",")]
    [InlineData("{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":1}}}},\"type\":\"flow.open\",\"id\":\"x\"}")]
    public void RejectsGarbage(string line) => Assert.Null(FlowEventParser.TryParse(line));

    [Fact]
    public void IgnoresWrongFieldTypesAndCapsStrings()
    {
        var longPath = new string('a', 5000);
        var parsed = FlowEventParser.TryParse(
            "{\"type\":\"flow.stats\",\"id\":\"f\",\"pid\":\"12\",\"remotePort\":70000," +
            "\"bytesIn\":-5,\"bytesOut\":12.5,\"path\":\"" + longPath + "\"}");

        Assert.NotNull(parsed);
        Assert.Equal(0, parsed.ProcessId);
        Assert.Equal(0, parsed.RemotePort);
        Assert.Null(parsed.BytesIn);
        Assert.Null(parsed.BytesOut);
        Assert.Equal(FlowEventParser.MaxStringLength, parsed.Path.Length);
    }

    [Fact]
    public async Task LineReaderDropsOversizedLinesAndContinues()
    {
        var text = "first\n" + new string('x', 100) + "\nsecond\r\nlast";
        var reader = new BoundedLineReader(new MemoryStream(Encoding.UTF8.GetBytes(text)), 50);

        Assert.Equal("first", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("second", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("last", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Null(await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal(1, reader.DroppedLines);
    }

    [Fact]
    public async Task ServerConsumesStreamRobustly()
    {
        using var temp = new TempDirectory();
        var flows = new FlowTable();
        var status = new FilterStatus();
        var server = new FilterEventServer(
            MacServicePaths.ForRoot(temp.Path), flows, status, _ => true, new ManualTimeProvider(Start));

        var huge = "{\"type\":\"flow.open\",\"id\":\"" + new string('h', FilterEventServer.MaxLineBytes * 2) + "\"}";
        var stream = string.Join('\n',
            "{\"type\":\"filter.hello\",\"version\":\"0.1\",\"generation\":3}",
            "not json at all",
            huge,
            OpenCurl,
            "{\"type\":\"flow.stats\",\"id\":\"missing\",\"bytesIn\":1}",
            "",
            "\u0000\u0001binary");

        var connection = status.ClientConnected();
        await server.ConsumeAsync(new MemoryStream(Encoding.UTF8.GetBytes(stream)), connection, CancellationToken.None);
        status.ClientDisconnected(connection);

        Assert.Equal(1, flows.Count);
        Assert.Equal(3, server.AcceptedEvents);
        Assert.Equal(3, server.RejectedLines);
        Assert.Equal(1, flows.OrphanEvents);
        Assert.Equal("0.1", status.Version);
        Assert.Equal(3, status.LoadedGeneration);
    }

    [Fact]
    public void ConnectionSourceAggregatesFlowLifecycle()
    {
        var time = new ManualTimeProvider(Start);
        var flows = new FlowTable();
        var status = new FilterStatus();
        var source = new MacConnectionSource(flows, status, PathOnlyIdentitySource.Instance, () => [], time);
        var connection = status.ClientConnected();

        void Feed(string json)
        {
            var parsed = FlowEventParser.TryParse(json)!;
            status.EventSeen(connection, time.GetUtcNow());
            flows.Apply(parsed, time.GetUtcNow());
        }

        Feed(OpenCurl);
        Feed("{\"type\":\"flow.open\",\"id\":\"b1\",\"pid\":77,\"path\":\"/Applications/Safari.app/Contents/MacOS/Safari\"," +
             "\"direction\":\"outbound\",\"protocol\":\"udp\",\"remoteAddress\":\"10.0.0.1\",\"remotePort\":53," +
             "\"verdict\":\"block\",\"ruleId\":\"r1\"}");

        var first = source.Capture(CancellationToken.None);
        Assert.Equal(MacConnectionSource.FlowSourceName, first.SourceName);
        Assert.Equal(2, first.Connections.Count);
        Assert.Equal(2, first.ProcessCount);

        var curl = first.Connections.Single(connection => connection.ProcessId == 4242);
        Assert.Equal("curl", curl.AppDisplayName);
        Assert.Equal("/usr/bin/curl", curl.AppPath);
        Assert.Equal(TransportProtocol.Tcp, curl.Protocol);
        Assert.Equal("192.168.64.5:50123", curl.LocalEndpoint);
        Assert.Equal("93.184.216.34:443", curl.RemoteEndpoint);
        Assert.Equal("example.com", curl.RemoteHost);
        Assert.Equal(ConnectionDirection.Outbound, curl.Direction);
        Assert.Equal("Established", curl.State);
        Assert.True(curl.IsNew);

        var blocked = first.Connections.Single(connection => connection.ProcessId == 77);
        Assert.Equal("Safari", blocked.AppDisplayName);
        Assert.Equal("Blocked", blocked.State);
        Assert.Equal(ConnectionRuleStatus.BlockedByOwnedRule, blocked.RuleStatus);

        time.Advance(TimeSpan.FromSeconds(2));
        Feed("{\"type\":\"flow.stats\",\"id\":\"f1\",\"bytesIn\":4000,\"bytesOut\":1000}");
        var second = source.Capture(CancellationToken.None);
        var stats = Assert.Single(second.Connections);
        Assert.Equal(4000, stats.ObservedBytesReceived);
        Assert.Equal(1000, stats.ObservedBytesSent);
        Assert.Equal(2000, stats.EstimatedDownloadBytesPerSecond);
        Assert.Equal(500, stats.EstimatedUploadBytesPerSecond);

        // A reordered smaller counter never moves totals back.
        Feed("{\"type\":\"flow.stats\",\"id\":\"f1\",\"bytesIn\":10,\"bytesOut\":10}");
        time.Advance(TimeSpan.FromSeconds(1));
        Feed("{\"type\":\"flow.close\",\"id\":\"f1\",\"bytesIn\":6000,\"bytesOut\":1500}");
        var third = source.Capture(CancellationToken.None);
        var closed = Assert.Single(third.Connections);
        Assert.Equal("Closed", closed.State);
        Assert.Equal(6000, closed.ObservedBytesReceived);
        Assert.Equal(2000, closed.EstimatedDownloadBytesPerSecond);

        Assert.Empty(source.Capture(CancellationToken.None).Connections);
    }

    [Fact]
    public void ConnectionSourceFallsBackToLibProcWithoutFilter()
    {
        var time = new ManualTimeProvider(Start);
        var sockets = new List<LibProcSocket>
        {
            new(10, true, System.Net.IPAddress.Any, 22, System.Net.IPAddress.Any, 0, LibProcLayout.TcpStateListen),
            new(10, true, System.Net.IPAddress.Parse("192.168.64.5"), 22, System.Net.IPAddress.Parse("192.168.64.1"), 50000, 4),
            new(20, true, System.Net.IPAddress.Parse("192.168.64.5"), 50001, System.Net.IPAddress.Parse("1.1.1.1"), 443, 4),
            new(30, false, System.Net.IPAddress.Loopback, 53, System.Net.IPAddress.Any, 0, -1),
        };
        var source = new MacConnectionSource(new FlowTable(), new FilterStatus(), PathOnlyIdentitySource.Instance, () => sockets, time);

        var snapshot = source.Capture(CancellationToken.None);

        Assert.Equal(MacConnectionSource.LibProcSourceName, snapshot.SourceName);
        Assert.Equal(4, snapshot.Connections.Count);
        Assert.Equal(3, snapshot.ProcessCount);
        Assert.Contains(snapshot.Limitations, text => text.Contains("not streaming", StringComparison.Ordinal));
        Assert.Equal(ConnectionDirection.Inbound, snapshot.Connections[1].Direction);
        Assert.Equal(ConnectionDirection.Outbound, snapshot.Connections[2].Direction);
        Assert.Equal("Listen", snapshot.Connections[0].State);
        Assert.Equal("—", snapshot.Connections[0].RemoteEndpoint);
        Assert.True(snapshot.Connections[3].IsLoopback);
        Assert.All(snapshot.Connections, connection => Assert.Equal(DataQuality.Partial, connection.Quality));

        // Filter events take over as soon as they stream.
        var status = new FilterStatus();
        _ = status.ClientConnected();
        var streaming = new MacConnectionSource(new FlowTable(), status, PathOnlyIdentitySource.Instance, () => sockets, time);
        Assert.Equal(MacConnectionSource.FlowSourceName, streaming.Capture(CancellationToken.None).SourceName);
    }

    [Fact]
    public void FlowTableIsBounded()
    {
        var table = new FlowTable();
        for (var index = 0; index < FlowTable.MaxFlows + 10; index++)
        {
            table.Apply(new FlowEvent { Type = FlowEventType.Open, Id = "f" + index }, Start);
        }

        Assert.Equal(FlowTable.MaxFlows, table.Count);
        Assert.Equal(10, table.EvictedFlows);
    }
}
