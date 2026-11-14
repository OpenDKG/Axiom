// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
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

    [Fact]
    public async Task Rediscover_upgrades_a_known_public_resolver_to_doh_like_the_start_path()
    {
        var policy = PrivacyShieldPolicy.Create(new PrivacyShieldSettings { Categories = PrivacyCategory.None });
        await using var server = new DnsProxyServer(policy, [Dns("10.0.2.3")], port: 0);
        var platform = new ScriptedPlatform { Upstreams = [Dns("1.1.1.1"), Dns("192.168.1.1")] };
        var log = new List<string>();

        Assert.True(UpstreamRediscovery.Rediscover(server, platform, log.Add));

        // Same selection as PrivacyShieldController at start: DnsUpstream.UpgradeEndpoints.
        Assert.Equal("https://1.1.1.1/dns-query (DoH), 192.168.1.1:53", server.Upstream);
        Assert.Equal([Dns("1.1.1.1"), Dns("192.168.1.1")], server.Upstreams);
        Assert.True(server.Targets[0].IsDoh);
        Assert.False(server.Targets[0].FallbackToPlainAllowed);
        Assert.False(server.Targets[1].IsDoh);
        Assert.Contains("prefer DoH", server.Snapshot(new PrivacyShieldSettings()).Detail, StringComparison.Ordinal);

        // The same discovery again is not a change (compared on the plain endpoints).
        Assert.False(UpstreamRediscovery.Rediscover(server, platform, log.Add));
    }

    [Fact]
    public async Task A_swap_to_a_doh_target_after_a_plain_start_is_served_over_doh()
    {
        var requests = 0;
        using var doh = new FakeDohHandler(request =>
        {
            Interlocked.Increment(ref requests);
            var wire = request.Content!.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            wire[2] |= 0x80; // QR: the query echoed back as a NOERROR response
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(wire),
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
            return response;
        });
        var settings = new PrivacyShieldSettings { Categories = PrivacyCategory.None };
        await using var server = new DnsProxyServer(
            PrivacyShieldPolicy.Create(settings),
            [new DnsUpstreamTarget(Dns("192.0.2.1"))],
            port: 0,
            dohHandler: doh);
        Assert.Contains("plain UDP/TCP DNS", server.Snapshot(settings).Detail, StringComparison.Ordinal);

        server.UpdateTargets(DnsUpstream.UpgradeEndpoints([Dns("9.9.9.9")]));

        byte[] query =
        [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, (byte)'a', (byte)'l', (byte)'l', (byte)'o', (byte)'w', (byte)'e', (byte)'d',
            0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        using var client = new UdpClient(AddressFamily.InterNetwork);
        client.Connect(IPAddress.Loopback, server.Port);
        await client.SendAsync(query, query.Length);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var reply = await client.ReceiveAsync(timeout.Token);

        Assert.Equal(1, requests);
        Assert.Equal(0x12, reply.Buffer[0]);
        Assert.Equal(0x34, reply.Buffer[1]);
        Assert.Equal(0, reply.Buffer[3] & 0x0F);
        Assert.Equal("https://9.9.9.9/dns-query (DoH)", server.Upstream);
        Assert.Contains("encrypted with DoH", server.Snapshot(settings).Detail, StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => server.UpdateTargets([]));
        Assert.Throws<ArgumentException>(() => server.UpdateTargets([new DnsUpstreamTarget(null)]));
    }

    [Fact]
    public void Null_platform_warning_names_the_doh_fallback()
    {
        Assert.Contains(
            "using encrypted DoH fallback upstream DNS",
            NullPrivacyDnsPlatform.Instance.NoUpstreamWarning,
            StringComparison.Ordinal);
    }

    private sealed class FakeDohHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
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
