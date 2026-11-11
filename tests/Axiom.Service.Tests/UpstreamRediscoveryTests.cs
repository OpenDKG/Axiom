// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Sockets;
using Axiom.Contracts.Privacy;
using Axiom.Service.Hosting.Dns;
using Xunit;

namespace Axiom.Service.Tests;

/// <summary>Review #7: upstreams follow the system resolvers while the shield redirects DNS.</summary>
public sealed class UpstreamRediscoveryTests
{
    private static IPEndPoint Dns(string address) => new(IPAddress.Parse(address), 53);

    [Fact]
    public void Same_set_in_same_order_is_not_a_change()
    {
        IPEndPoint[] current = [Dns("10.0.2.3"), Dns("1.1.1.1")];

        Assert.Null(UpstreamRediscovery.Decide(current, [Dns("10.0.2.3"), Dns("1.1.1.1")]));
    }

    [Fact]
    public void Different_or_reordered_set_is_a_change()
    {
        IPEndPoint[] current = [Dns("10.0.2.3")];

        Assert.Equal([Dns("192.168.1.1")], UpstreamRediscovery.Decide(current, [Dns("192.168.1.1")]));
        Assert.Equal([Dns("1.1.1.1"), Dns("10.0.2.3")], UpstreamRediscovery.Decide([Dns("10.0.2.3"), Dns("1.1.1.1")], [Dns("1.1.1.1"), Dns("10.0.2.3")]));
    }

    [Fact]
    public void Loopback_is_never_an_upstream_and_an_empty_discovery_keeps_the_current_list()
    {
        IPEndPoint[] current = [Dns("10.0.2.3")];

        // The system points at this resolver (127.0.0.1): not a usable upstream.
        Assert.Null(UpstreamRediscovery.Decide(current, [Dns("127.0.0.1")]));
        Assert.Null(UpstreamRediscovery.Decide(current, [Dns("::1")]));
        Assert.Null(UpstreamRediscovery.Decide(current, []));

        // Loopback entries are dropped from a mixed discovery; duplicates too.
        Assert.Equal([Dns("9.9.9.9")], UpstreamRediscovery.Decide(current, [Dns("127.0.0.1"), Dns("9.9.9.9"), Dns("9.9.9.9")]));
    }

    [Fact]
    public void Discovery_is_due_every_ten_seconds_or_every_two_while_failing()
    {
        var start = new DateTimeOffset(2026, 11, 11, 10, 0, 0, TimeSpan.Zero);

        Assert.False(UpstreamRediscovery.IsDue(start, start.AddSeconds(9), failureStreak: 0));
        Assert.True(UpstreamRediscovery.IsDue(start, start.AddSeconds(10), failureStreak: 0));
        Assert.False(UpstreamRediscovery.IsDue(start, start.AddSeconds(2), failureStreak: UpstreamRediscovery.FailureStreakThreshold - 1));
        Assert.True(UpstreamRediscovery.IsDue(start, start.AddSeconds(2), failureStreak: UpstreamRediscovery.FailureStreakThreshold));
    }

    [Fact]
    public async Task Proxy_swaps_upstreams_live_without_dropping_the_listener()
    {
        var policy = PrivacyShieldPolicy.Create(new PrivacyShieldSettings { Categories = PrivacyCategory.None });
        await using var server = new DnsProxyServer(policy, [Dns("10.0.2.3")], port: 0);
        var port = server.Port;

        server.UpdateUpstreams([Dns("192.168.1.1"), Dns("1.1.1.1")]);

        Assert.Equal(port, server.Port);
        Assert.Equal("192.168.1.1:53, 1.1.1.1:53", server.Upstream);
        Assert.Equal(0, server.UpstreamFailureStreak);
        Assert.Throws<ArgumentException>(() => server.UpdateUpstreams([]));

        // The listener is still bound: a second bind on the same port fails.
        using var probe = new UdpClient(AddressFamily.InterNetwork);
        Assert.Throws<SocketException>(() => probe.Client.Bind(new IPEndPoint(IPAddress.Loopback, port)));
    }

    [Fact]
    public async Task Rediscover_swaps_the_server_upstreams_when_discovery_changes_and_logs_it()
    {
        var policy = PrivacyShieldPolicy.Create(new PrivacyShieldSettings { Categories = PrivacyCategory.None });
        await using var server = new DnsProxyServer(policy, [Dns("10.0.2.3")], port: 0);
        var platform = new ScriptedPlatform { Upstreams = [Dns("10.0.2.3")] };
        var log = new List<string>();

        // Unchanged network: nothing to do, nothing logged.
        Assert.False(UpstreamRediscovery.Rediscover(server, platform, log.Add));
        Assert.Empty(log);

        // Network changed: the new resolver is swapped in and the change is traceable in the log.
        platform.Upstreams = [Dns("192.168.1.1")];
        Assert.True(UpstreamRediscovery.Rediscover(server, platform, log.Add));
        Assert.Equal("192.168.1.1:53", server.Upstream);
        Assert.Contains("upstreams changed: 10.0.2.3:53 -> 192.168.1.1:53", log);

        // The system now points at us (127.0.0.1) and no backup is known: keep what works.
        platform.Upstreams = [Dns("127.0.0.1")];
        Assert.False(UpstreamRediscovery.Rediscover(server, platform, log.Add));
        Assert.Equal("192.168.1.1:53", server.Upstream);

        // A failing discovery is logged and leaves the server untouched.
        platform.Throw = true;
        Assert.False(UpstreamRediscovery.Rediscover(server, platform, log.Add));
        Assert.Contains(log, line => line.StartsWith("upstream rediscovery failed", StringComparison.Ordinal));
        Assert.Equal(4, platform.Calls);
    }

    [Fact]
    public async Task Watch_stops_on_cancellation()
    {
        var policy = PrivacyShieldPolicy.Create(new PrivacyShieldSettings { Categories = PrivacyCategory.None });
        await using var server = new DnsProxyServer(policy, [Dns("10.0.2.3")], port: 0);
        var log = new List<string>();
        using var cancellation = new CancellationTokenSource();

        var watch = UpstreamRediscovery.WatchAsync(server, new ScriptedPlatform(), log.Add, cancellation.Token);
        await cancellation.CancelAsync();
        await watch.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Contains(log, line => line.StartsWith("upstream rediscovery active", StringComparison.Ordinal));
    }

    private sealed class ScriptedPlatform : IPrivacyDnsPlatform
    {
        public IReadOnlyList<IPEndPoint> Upstreams { get; set; } = [];

        public int Calls { get; private set; }

        public bool Throw { get; set; }

        public IDnsAppAttributor? Attributor => null;

        public string NoUpstreamWarning => "none";

        public bool RediscoversUpstreams => true;

        public IReadOnlyList<IPEndPoint> DiscoverUpstreams()
        {
            Calls++;
            return Throw ? throw new InvalidOperationException("scutil failed") : Upstreams;
        }

        public string? OnResolverStarted(int port) => null;

        public bool RestoreIfNeeded() => false;
    }
}
