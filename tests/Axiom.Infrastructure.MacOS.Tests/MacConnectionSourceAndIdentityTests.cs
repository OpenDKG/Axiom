// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Infrastructure.MacOS.Monitoring;
using Axiom.Infrastructure.MacOS.ProcessIdentity;

namespace Axiom.Infrastructure.MacOS.Tests;

/// <summary>Review test gaps: MacConnectionSource aggregation/direction/dedupe, MacProcessIdentityResolver cache/promotion.</summary>
public sealed class MacConnectionSourceAndIdentityTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 11, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void LibProcFallbackDedupesDescriptorsAndClassifiesDirection()
    {
        var time = new ManualTimeProvider(Start);
        var listen = new LibProcSocket(10, true, IPAddress.Any, 8080, IPAddress.Any, 0, LibProcLayout.TcpStateListen);
        var accepted = new LibProcSocket(10, true, IPAddress.Parse("10.0.2.15"), 8080, IPAddress.Parse("10.0.2.2"), 51000, 4);
        var outbound = new LibProcSocket(20, true, IPAddress.Parse("10.0.2.15"), 51001, IPAddress.Parse("1.1.1.1"), 443, 4);
        var mappedOutbound = new LibProcSocket(20, true, IPAddress.Parse("::ffff:10.0.2.15"), 51002, IPAddress.Parse("::ffff:1.1.1.1"), 443, 4);
        var udp = new LibProcSocket(30, false, IPAddress.Loopback, 5353, IPAddress.Any, 0, -1);
        // The accepted socket appears twice (dup'd fd / forked worker holding the same socket).
        var sockets = new List<LibProcSocket> { listen, accepted, accepted, outbound, mappedOutbound, udp, udp };
        var source = new MacConnectionSource(new FlowTable(), new FilterStatus(), PathOnlyIdentitySource.Instance, () => sockets, time);

        var snapshot = source.Capture(CancellationToken.None);

        Assert.Equal(5, snapshot.Connections.Count);
        Assert.Equal(3, snapshot.ProcessCount);
        var byEndpoint = snapshot.Connections.ToDictionary(connection => connection.LocalEndpoint + ">" + connection.RemoteEndpoint);
        Assert.Equal(ConnectionDirection.Inbound, byEndpoint["0.0.0.0:8080>—"].Direction);
        Assert.Equal(ConnectionDirection.Inbound, byEndpoint["10.0.2.15:8080>10.0.2.2:51000"].Direction);
        Assert.Equal(ConnectionDirection.Outbound, byEndpoint["10.0.2.15:51001>1.1.1.1:443"].Direction);
        Assert.Equal(ConnectionDirection.Outbound, byEndpoint["10.0.2.15:51002>1.1.1.1:443"].Direction);
        Assert.Equal(ConnectionDirection.Unknown, byEndpoint["127.0.0.1:5353>—"].Direction);
        Assert.True(byEndpoint["127.0.0.1:5353>—"].IsLoopback);
        Assert.Equal("Established", byEndpoint["10.0.2.15:51001>1.1.1.1:443"].State);
        Assert.Equal("Bound", byEndpoint["127.0.0.1:5353>—"].State);
        Assert.All(snapshot.Connections, connection => Assert.True(connection.IsNew));

        // First-seen is stable across polls; IsNew expires after 60 s.
        time.Advance(TimeSpan.FromSeconds(61));
        var later = source.Capture(CancellationToken.None);
        Assert.All(later.Connections, connection => Assert.Equal(Start, connection.FirstObservedUtc));
        Assert.All(later.Connections, connection => Assert.False(connection.IsNew));
    }

    [Fact]
    public void FlowSnapshotMapsVerdictDirectionAndAggregatesProcesses()
    {
        var time = new ManualTimeProvider(Start);
        var flows = new FlowTable();
        var status = new FilterStatus();
        status.ClientConnected();
        status.EventSeen(Start);
        flows.Apply(Flow("f1", 100, "/usr/bin/curl", "outbound", "tcp", "93.184.216.34", 443, "allow", null), Start);
        flows.Apply(Flow("f2", 100, "/usr/bin/curl", "outbound", "udp", "1.1.1.1", 53, "block", "rule-1"), Start);
        flows.Apply(Flow("f3", 200, "/usr/sbin/sshd", "inbound", "tcp", "10.0.2.2", 22, "block", null), Start);
        flows.Apply(Flow("f4", 300, "/x", "outbound", "icmp", "10.0.2.2", 0, "allow", null), Start);
        var source = new MacConnectionSource(flows, status, PathOnlyIdentitySource.Instance, null, time);

        var snapshot = source.Capture(CancellationToken.None);

        Assert.Equal(MacConnectionSource.FlowSourceName, snapshot.SourceName);
        Assert.Equal(3, snapshot.Connections.Count);
        Assert.Equal(2, snapshot.ProcessCount);
        Assert.Contains(snapshot.Limitations, text => text.Contains("1 non-TCP/UDP flow(s) omitted", StringComparison.Ordinal));
        var byRemote = snapshot.Connections.ToDictionary(connection => connection.RemoteEndpoint);
        Assert.Equal(ConnectionRuleStatus.Unknown, byRemote["93.184.216.34:443"].RuleStatus);
        Assert.Equal(ConnectionRuleStatus.BlockedByOwnedRule, byRemote["1.1.1.1:53"].RuleStatus);
        Assert.Equal(ConnectionRuleStatus.BlockedByExternalPolicy, byRemote["10.0.2.2:22"].RuleStatus);
        Assert.Equal(ConnectionDirection.Inbound, byRemote["10.0.2.2:22"].Direction);
        Assert.Equal(ConnectionDirection.Outbound, byRemote["1.1.1.1:53"].Direction);
        Assert.Equal(TransportProtocol.Udp, byRemote["1.1.1.1:53"].Protocol);
        Assert.Equal("curl", byRemote["1.1.1.1:53"].AppDisplayName);
        Assert.All(snapshot.Connections, connection => Assert.Equal(DataQuality.Observed, connection.Quality));
    }

    [Fact]
    public void IdentityResolverCachesPerPidAndPromotesTheSignatureWhenTheBackgroundCheckFinishes()
    {
        using var temp = new TempDirectory();
        var bundle = Path.Combine(temp.Path, "Foo.app");
        Directory.CreateDirectory(Path.Combine(bundle, "Contents", "MacOS"));
        File.WriteAllText(Path.Combine(bundle, "Contents", "Info.plist"), """
            <?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict>
            <key>CFBundleIdentifier</key><string>com.example.foo</string>
            <key>CFBundleName</key><string>Foo</string>
            <key>CFBundleShortVersionString</key><string>1.2</string>
            </dict></plist>
            """);
        var executable = Path.Combine(bundle, "Contents", "MacOS", "Foo");
        var time = new ManualTimeProvider(Start);
        var pathCalls = 0;
        using var gate = new ManualResetEventSlim(false);
        var runner = new FakeRunner()
            .On("codesign -dv", _ =>
            {
                gate.Wait(TimeSpan.FromSeconds(10));
                return new ProcessResult(0, string.Empty, $"Executable={executable}\nIdentifier=com.example.foo\nAuthority=Developer ID Application: Example Corp (ABCDE12345)\nAuthority=Developer ID Certification Authority\nTeamIdentifier=ABCDE12345\n");
            })
            .On("codesign --verify", _ => new ProcessResult(0, string.Empty, string.Empty));
        var resolver = new MacProcessIdentityResolver(
            runner,
            pid => { pathCalls++; return pid == 10 ? executable : pid == 50 ? "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal" : string.Empty; },
            pid => pid switch
            {
                10 => new LibProcBsdInfo(10, 50, 501, "Foo", "Foo"),
                50 => new LibProcBsdInfo(50, 1, 501, "Terminal", "Terminal"),
                1 => new LibProcBsdInfo(1, 0, 0, "launchd", "launchd"),
                _ => null,
            },
            time);

        var first = resolver.Resolve(10, null);
        Assert.Equal("Foo", first.DisplayName);
        Assert.Equal(bundle, first.BundlePath);
        Assert.Equal("com.example.foo", first.BundleId);
        Assert.Equal("1.2", first.Version);
        Assert.Equal(50, first.ParentProcessId);
        Assert.Equal("Terminal", first.ParentProcessName);
        Assert.Equal("Terminal", first.ParentChain); // the chain stops before launchd (pid 1)
        Assert.Equal("Pending", first.SignatureStatus);
        Assert.Equal(2, pathCalls);

        // Cached: no libproc call while the entry is fresh.
        var second = resolver.Resolve(10, null);
        Assert.Equal(2, pathCalls);
        Assert.Equal("Pending", second.SignatureStatus);

        // Promotion: once the background codesign completes, the cached identity reports it.
        gate.Set();
        CodeSignatureInfo? signature = null;
        for (var attempt = 0; attempt < 200 && signature is null; attempt++)
        {
            Thread.Sleep(10);
            signature = resolver.TryGetSignature(bundle);
        }

        Assert.NotNull(signature);
        var promoted = resolver.Resolve(10, null);
        Assert.Equal("Valid", promoted.SignatureStatus);
        Assert.Equal("Developer ID Application: Example Corp (ABCDE12345)", promoted.SignerName);
        Assert.Equal("ABCDE12345", promoted.TeamId);
        Assert.Equal(2, pathCalls);
        Assert.Equal(2, runner.Calls.Count(call => call.StartsWith("codesign", StringComparison.Ordinal)));

        // A known path that differs from the cached one (pid reuse) re-resolves (parent name only:
        // the path is given); an expired entry re-resolves fully (own path + parent name).
        var reused = resolver.Resolve(10, "/usr/bin/other");
        Assert.Equal("other", reused.DisplayName);
        Assert.Equal(3, pathCalls);
        time.Advance(MacProcessIdentityResolver.PidCacheLifetime + TimeSpan.FromSeconds(1));
        resolver.Resolve(10, null);
        Assert.Equal(5, pathCalls);
    }

    private static FlowEvent Flow(string id, int pid, string path, string direction, string protocol, string remote, int port, string verdict, string? ruleId) =>
        new()
        {
            Type = FlowEventType.Open,
            Id = id,
            ProcessId = pid,
            Path = path,
            Direction = direction,
            Protocol = protocol,
            LocalAddress = "10.0.2.15",
            LocalPort = 50000 + pid,
            RemoteAddress = remote,
            RemotePort = port,
            Verdict = verdict,
            RuleId = ruleId,
            Timestamp = Start,
        };
}
