// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.Linux.Firewall;
using Axiom.Infrastructure.Linux.Monitoring;
using Axiom.Infrastructure.Linux.ProcessIdentity;
using Axiom.Infrastructure.Unix.Filter;
using Axiom.Infrastructure.Unix.Monitoring;

namespace Axiom.Infrastructure.Linux.Tests;

/// <summary>The engine → daemon glue: NDJSON lines land in FilterStatus/FlowTable, blocks reach the connection snapshot.</summary>
[System.Runtime.Versioning.SupportedOSPlatform("linux")]
public sealed class EnforcementWiringTests
{
    [Fact]
    public void FilterEventPipeFeedsStatusAndFlowTableAndCountsGarbage()
    {
        using var temp = new TempDirectory();
        var status = new FilterStatus();
        var flows = new FlowTable();
        var pipe = new FilterEventPipe(new FilterEventServer(LinuxServicePaths.ForRoot(temp.Path), flows, status));

        pipe.Emit("{\"type\":\"filter.hello\",\"ts\":\"2026-11-12T10:00:00.000Z\",\"version\":\"nft-1\",\"generation\":7,\"dropped\":0}");
        pipe.Emit("{\"type\":\"filter.rules\",\"ts\":\"2026-11-12T10:00:00.000Z\",\"generation\":7,\"applied\":2,\"rejected\":[{\"id\":\"0f8fad5b-d9cb-469f-a165-70867728950e\",\"reason\":\"hostnames are not supported\"}],\"error\":null,\"dropped\":0}");
        pipe.Emit("{\"type\":\"flow.open\",\"id\":\"nft-1-1\",\"ts\":\"2026-11-12T10:00:01.000Z\",\"pid\":4242,\"path\":\"/usr/bin/curl\",\"direction\":\"outbound\",\"protocol\":\"tcp\",\"localAddress\":\"192.168.70.4\",\"localPort\":39148,\"remoteAddress\":\"104.20.23.154\",\"remotePort\":443,\"remoteHost\":null,\"verdict\":\"block\",\"ruleId\":\"c7d05fe4-ae68-59b7-90f4-eed017f7aab3\",\"responsiblePid\":null,\"responsiblePath\":null}");
        pipe.Emit("not json");

        Assert.Equal("nft-1", status.Version);
        Assert.Equal(7, status.LoadedGeneration);
        Assert.NotNull(status.Rules);
        Assert.Equal(2, status.Rules!.Applied);
        Assert.Single(status.Rules.Rejected);
        Assert.Equal(1, flows.Count);
        Assert.Equal(1, pipe.RejectedLines);
    }

    [Fact]
    public void ConnectionSourceListsTracedBlocksNextToProcSockets()
    {
        var time = new FixedTime(new DateTimeOffset(2026, 11, 12, 10, 0, 5, TimeSpan.Zero));
        var flows = new FlowTable();
        flows.Apply(FlowEventParser.TryParse("{\"type\":\"flow.open\",\"id\":\"nft-1-1\",\"ts\":\"2026-11-12T10:00:01.000Z\",\"pid\":4242,\"path\":\"/usr/bin/curl\",\"direction\":\"outbound\",\"protocol\":\"tcp\",\"localAddress\":\"192.168.70.4\",\"localPort\":39148,\"remoteAddress\":\"104.20.23.154\",\"remotePort\":443,\"remoteHost\":null,\"verdict\":\"block\",\"ruleId\":\"c7d05fe4-ae68-59b7-90f4-eed017f7aab3\",\"responsiblePid\":null,\"responsiblePath\":null}")!, time.GetUtcNow());
        var sockets = new List<ProcSocket>
        {
            new(1000, true, IPAddress.Parse("192.168.70.4"), 40000, IPAddress.Parse("1.1.1.1"), 443, ProcNetTable.TcpStateEstablished, 1000, 12345),
        };
        var source = new LinuxConnectionSource(() => sockets, new PathOnlyIdentities(), time, privileged: true, flows);

        var snapshot = source.Capture(CancellationToken.None);

        Assert.Equal(2, snapshot.Connections.Count);
        var blocked = Assert.Single(snapshot.Connections, connection => connection.RuleStatus == ConnectionRuleStatus.BlockedByOwnedRule);
        Assert.Equal("/usr/bin/curl", blocked.AppPath);
        Assert.Equal(4242, blocked.ProcessId);
        Assert.Equal("104.20.23.154:443", blocked.RemoteEndpoint);
        Assert.Equal(ConnectionDirection.Outbound, blocked.Direction);
        Assert.Equal(DataQuality.Observed, blocked.Quality);
        Assert.Contains(snapshot.Limitations, limitation => limitation.Contains("nftables trace", StringComparison.Ordinal));
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class PathOnlyIdentities : ILinuxProcessIdentitySource
    {
        public LinuxProcessIdentity Resolve(int processId, string? knownPath) => new()
        {
            ProcessId = processId,
            Path = knownPath ?? string.Empty,
            DisplayName = Path.GetFileName(knownPath ?? string.Empty),
            Uid = 1000,
        };
    }
}
