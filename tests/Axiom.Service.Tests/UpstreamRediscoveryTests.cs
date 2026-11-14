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

    /// <summary>Pre-0.24.0 selection: follow the system resolvers, plain where they are not known public ones.</summary>
    private static readonly PrivacyShieldSettings FollowSystem = new() { EncryptDnsViaDoh = false };

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
        Assert.False(UpstreamRediscovery.Rediscover(server, platform, log.Add, FollowSystem));
        Assert.Empty(log);

        // Network changed: the new resolver is swapped in and the change is traceable in the log.
        platform.Upstreams = [Dns("192.168.1.1")];
        Assert.True(UpstreamRediscovery.Rediscover(server, platform, log.Add, FollowSystem));
        Assert.Equal("192.168.1.1:53", server.Upstream);
        Assert.Contains("upstreams changed: 10.0.2.3:53 -> 192.168.1.1:53", log);

        // The system now points at us (127.0.0.1) and no backup is known: keep what works.
        platform.Upstreams = [Dns("127.0.0.1")];
        Assert.False(UpstreamRediscovery.Rediscover(server, platform, log.Add, FollowSystem));
        Assert.Equal("192.168.1.1:53", server.Upstream);

        // A failing discovery is logged and leaves the server untouched.
        platform.Throw = true;
        Assert.False(UpstreamRediscovery.Rediscover(server, platform, log.Add, FollowSystem));
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

        var watch = UpstreamRediscovery.WatchAsync(server, new ScriptedPlatform(), log.Add, FollowSystem, cancellation.Token);
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

        Assert.True(UpstreamRediscovery.Rediscover(server, platform, log.Add, FollowSystem));

        // Same selection as PrivacyShieldController at start: DnsUpstream.UpgradeEndpoints.
        Assert.Equal("https://1.1.1.1/dns-query (DoH), 192.168.1.1:53", server.Upstream);
        Assert.Equal([Dns("1.1.1.1"), Dns("192.168.1.1")], server.Upstreams);
        Assert.True(server.Targets[0].IsDoh);
        Assert.False(server.Targets[0].FallbackToPlainAllowed);
        Assert.False(server.Targets[1].IsDoh);
        Assert.Contains("prefer DoH", server.Snapshot(new PrivacyShieldSettings()).Detail, StringComparison.Ordinal);

        // The same discovery again is not a change (compared on the plain endpoints).
        Assert.False(UpstreamRediscovery.Rediscover(server, platform, log.Add, FollowSystem));
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

    /// <summary>
    /// v0.24.0 default (EncryptDnsViaDoh, no explicit upstream) on a network whose resolver is a
    /// plain router: the start path forwards to the default DoH pair. A rediscovery must make the
    /// same selection and must not swap the router in as a plain upstream.
    /// </summary>
    [Fact]
    public async Task Rediscover_keeps_the_default_doh_pair_when_the_system_resolver_is_plain()
    {
        var settings = new PrivacyShieldSettings { Categories = PrivacyCategory.None };
        Assert.True(settings.EncryptDnsViaDoh);
        var policy = PrivacyShieldPolicy.Create(settings);
        var start = DnsUpstream.SelectSystemTargets([Dns("192.168.1.1")], settings.EncryptDnsViaDoh);
        Assert.Equal(DnsUpstream.DefaultDohTargets(), start);
        await using var server = new DnsProxyServer(policy, start, port: 0);
        var platform = new ScriptedPlatform { Upstreams = [Dns("192.168.1.1")] };
        var log = new List<string>();

        Assert.False(UpstreamRediscovery.Rediscover(server, platform, log.Add, settings));
        platform.Upstreams = [Dns("10.0.0.1"), Dns("192.168.1.1")];
        Assert.False(UpstreamRediscovery.Rediscover(server, platform, log.Add, settings));

        Assert.Equal("https://1.1.1.1/dns-query (DoH), https://9.9.9.9/dns-query (DoH)", server.Upstream);
        Assert.All(server.Targets, target => Assert.True(target.IsDoh && !target.FallbackToPlainAllowed));
        Assert.Empty(log);

        // A network whose own resolver is a known public one: that DoH endpoint only, never the plain router next to it.
        platform.Upstreams = [Dns("192.168.1.1"), Dns("8.8.8.8")];
        Assert.True(UpstreamRediscovery.Rediscover(server, platform, log.Add, settings));
        Assert.Equal("https://8.8.8.8/dns-query (DoH)", server.Upstream);
    }

    /// <summary>With EncryptDnsViaDoh off the system resolvers are followed as before (plain where not a known public one).</summary>
    [Fact]
    public async Task Rediscover_follows_plain_system_resolvers_only_when_encryption_is_switched_off()
    {
        var settings = new PrivacyShieldSettings { Categories = PrivacyCategory.None, EncryptDnsViaDoh = false };
        var policy = PrivacyShieldPolicy.Create(settings);
        await using var server = new DnsProxyServer(
            policy, DnsUpstream.SelectSystemTargets([Dns("10.0.2.3")], encryptDnsViaDoh: false), port: 0);
        var platform = new ScriptedPlatform { Upstreams = [Dns("192.168.1.1")] };

        Assert.True(UpstreamRediscovery.Rediscover(server, platform, _ => { }, settings));
        Assert.Equal("192.168.1.1:53", server.Upstream);
    }

    /// <summary>An explicit upstream (IP, list or DoH URL) is the user's choice: discovery never replaces it.</summary>
    [Theory]
    [InlineData("https://dns.quad9.net/dns-query")]
    [InlineData("9.9.9.9, 1.1.1.1")]
    [InlineData("udp://192.168.50.1")]
    public async Task An_explicit_upstream_is_never_replaced_by_discovery(string upstream)
    {
        var settings = new PrivacyShieldSettings { Categories = PrivacyCategory.None, UpstreamDns = upstream };
        var policy = PrivacyShieldPolicy.Create(settings);
        Assert.True(DnsUpstream.TryParseTargets(upstream, out var targets));
        await using var server = new DnsProxyServer(policy, targets, port: 0);
        var before = server.Upstream;
        var platform = new ScriptedPlatform { Upstreams = [Dns("192.168.1.1")] };

        Assert.False(UpstreamRediscovery.ShouldWatch(platform, settings));
        Assert.False(UpstreamRediscovery.Rediscover(server, platform, _ => { }, settings));
        Assert.Equal(before, server.Upstream);
        Assert.Equal(0, platform.Calls);
    }

    [Fact]
    public void Watch_runs_only_for_a_redirecting_platform_without_an_explicit_upstream()
    {
        var redirecting = new ScriptedPlatform();
        Assert.True(redirecting.RediscoversUpstreams);
        Assert.True(UpstreamRediscovery.ShouldWatch(redirecting, new PrivacyShieldSettings()));
        Assert.False(UpstreamRediscovery.ShouldWatch(NullPrivacyDnsPlatform.Instance, new PrivacyShieldSettings()));
    }

    /// <summary>The shared selection is upstream's v0.24.0 block (PrivacyShieldController.TryCreateServer).</summary>
    [Fact]
    public void System_target_selection_matches_upstream()
    {
        // Encrypt on: only the DoH members of the upgraded system list, or the default pair.
        Assert.Equal(DnsUpstream.DefaultDohTargets(), DnsUpstream.SelectSystemTargets([], true));
        Assert.Equal(DnsUpstream.DefaultDohTargets(), DnsUpstream.SelectSystemTargets([Dns("192.168.1.1")], true));
        Assert.Equal(
            DnsUpstream.UpgradeEndpoints([Dns("8.8.8.8")]),
            DnsUpstream.SelectSystemTargets([Dns("192.168.1.1"), Dns("8.8.8.8")], true));

        // Encrypt off: the upgraded system list as it is; empty stays empty (the caller then falls back with a warning).
        Assert.Empty(DnsUpstream.SelectSystemTargets([], false));
        Assert.Equal(
            DnsUpstream.UpgradeEndpoints([Dns("192.168.1.1"), Dns("8.8.8.8")]),
            DnsUpstream.SelectSystemTargets([Dns("192.168.1.1"), Dns("8.8.8.8")], false));

        Assert.Equal(
            ["https://1.1.1.1/dns-query (DoH)", "https://9.9.9.9/dns-query (DoH)"],
            DnsUpstream.DefaultDohTargets().Select(target => target.DisplayText));
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
