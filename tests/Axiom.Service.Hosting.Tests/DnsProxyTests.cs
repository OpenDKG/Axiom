// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers.Binary;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using Axiom.Contracts.Privacy;
using Axiom.Service.Hosting.Dns;
using Xunit;

namespace Axiom.Service.Hosting.Tests;

public sealed class DnsProxyTests
{
    [Fact]
    public void Query_parser_reads_the_question_name()
    {
        var query = BuildQuery("Blocked.Example");

        Assert.True(DnsProtocol.TryParseQuery(query, out var parsed));
        Assert.NotNull(parsed);
        Assert.Equal("blocked.example", parsed!.Domain);
        Assert.Equal(query.Length, parsed.QuestionEnd);
    }

    [Fact]
    public void Response_builder_sets_nxdomain_and_clears_answer_counts()
    {
        var query = BuildQuery("blocked.example");
        Assert.True(DnsProtocol.TryParseQuery(query, out var parsed));

        var response = DnsProtocol.BuildResponse(query, parsed!.QuestionEnd, 3);

        Assert.Equal(3, response[3] & 0x0F);
        Assert.True((response[2] & 0x80) != 0);
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6, 2)));
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(8, 2)));
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(10, 2)));
    }

    [Fact]
    public async Task Proxy_blocks_a_matching_domain_without_contacting_upstream()
    {
        var settings = new PrivacyShieldSettings
        {
            Categories = PrivacyCategory.None,
            BlockedDomains = ["blocked.example"],
        };
        var policy = PrivacyShieldPolicy.Create(settings);
        var recorded = new List<PrivacyShieldBlockedEvent>();
        await using var server = new DnsProxyServer(
            policy,
            [new IPEndPoint(IPAddress.Loopback, 9)],
            port: 0,
            onBlocked: recorded.Add);

        using var client = new UdpClient(AddressFamily.InterNetwork);
        client.Connect(IPAddress.Loopback, server.Port);
        var query = BuildQuery("ads.blocked.example");
        await client.SendAsync(query, query.Length);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var response = await client.ReceiveAsync(timeout.Token);

        Assert.Equal(3, response.Buffer[3] & 0x0F);
        var status = server.Snapshot(settings);
        Assert.Equal(1, status.Blocked);
        Assert.Contains(status.TopBlocked, item => item.Domain == "ads.blocked.example");
        Assert.Contains(status.RecentBlocked, item => item.Domain == "ads.blocked.example");
        Assert.Contains(recorded, item => item.Domain == "ads.blocked.example");
    }

    /// <summary>
    /// A server whose IPv4 TCP listener is up. With port 0 the proxy takes whatever port UDP gets and
    /// then tries it for TCP, where it may be taken or reserved. It carries on without TCP, which made
    /// the TCP tests flaky on CI runners (issue #374), and retrying the same way could keep failing. So
    /// ask the system for a port that is free for TCP first, and hand that one to the proxy.
    /// </summary>
    private static async Task<DnsProxyServer> CreateTcpCapableServerAsync(
        PrivacyShieldPolicy policy,
        Action<PrivacyShieldBlockedEvent>? onBlocked = null)
    {
        const int attempts = 10;
        for (var attempt = 1; attempt <= attempts; attempt++)
        {
            var port = FindFreeTcpPort();
            try
            {
                var server = new DnsProxyServer(policy, [new IPEndPoint(IPAddress.Loopback, 9)], port, onBlocked);
                if (HasIpv4TcpListener(server))
                {
                    return server;
                }

                await server.DisposeAsync();
            }
            catch (SocketException) when (attempt < attempts)
            {
                // The port is free for TCP but not for UDP.
            }

            await Task.Delay(50);
        }

        throw new InvalidOperationException($"The DNS proxy could not bind a TCP listener after {attempts} attempts.");
    }

    private static int FindFreeTcpPort()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        try
        {
            return ((IPEndPoint)probe.LocalEndpoint).Port;
        }
        finally
        {
            probe.Stop();
        }
    }

    // BindAddress says "UDP only" only when the IPv4 and IPv6 listeners both failed, and these tests
    // connect over IPv4.
    private static bool HasIpv4TcpListener(DnsProxyServer server) =>
        typeof(DnsProxyServer)
            .GetField("_tcp4", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(server) is not null;

    [Fact]
    public async Task Proxy_blocks_matching_domains_over_tcp()
    {
        var settings = new PrivacyShieldSettings
        {
            Categories = PrivacyCategory.None,
            BlockedDomains = ["blocked.example"],
        };
        var policy = PrivacyShieldPolicy.Create(settings);
        await using var server = await CreateTcpCapableServerAsync(policy);

        Assert.DoesNotContain("UDP only", server.BindAddress, StringComparison.Ordinal);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var client = new TcpClient(AddressFamily.InterNetwork);
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                await client.ConnectAsync(IPAddress.Loopback, server.Port, timeout.Token);
                break;
            }
            catch (SocketException) when (attempt < 10)
            {
                await Task.Delay(25, timeout.Token);
            }
        }

        using var stream = client.GetStream();
        var query = BuildQuery("blocked.example");
        await stream.WriteAsync(new byte[]
        {
            (byte)(query.Length >> 8),
            (byte)query.Length,
        }, timeout.Token);
        await stream.WriteAsync(query, timeout.Token);
        await stream.FlushAsync(timeout.Token);

        var lengthBytes = new byte[2];
        await stream.ReadExactlyAsync(lengthBytes, timeout.Token);
        var responseLength = (lengthBytes[0] << 8) | lengthBytes[1];
        var response = new byte[responseLength];
        await stream.ReadExactlyAsync(response, timeout.Token);

        Assert.Equal(3, response[3] & 0x0F);
        Assert.Equal(1, server.Snapshot(settings).Blocked);
    }

    [Fact]
    public async Task Proxy_forwards_allowed_queries_to_the_upstream()
    {
        using var upstream = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var upstreamPort = ((IPEndPoint)upstream.Client.LocalEndPoint!).Port;
        var settings = new PrivacyShieldSettings { Categories = PrivacyCategory.None };
        var policy = PrivacyShieldPolicy.Create(settings);
        await using var server = new DnsProxyServer(
            policy,
            [new IPEndPoint(IPAddress.Loopback, upstreamPort)],
            port: 0);

        var query = BuildQuery("allowed.example");
        using var client = new UdpClient(AddressFamily.InterNetwork);
        client.Connect(IPAddress.Loopback, server.Port);
        await client.SendAsync(query, query.Length);

        var received = await upstream.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(5));
        var response = DnsProtocol.BuildResponse(query, query.Length, 0);
        await upstream.SendAsync(response, response.Length, received.RemoteEndPoint);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var forwarded = await client.ReceiveAsync(timeout.Token);

        Assert.Equal(query[0], forwarded.Buffer[0]);
        Assert.Equal(query[1], forwarded.Buffer[1]);
        Assert.Equal(1, server.Snapshot(settings).Allowed);
    }

    [Fact]
    public void Response_must_match_the_transaction_id_and_question()
    {
        var query = BuildQuery("example.com");
        Assert.True(DnsProtocol.TryParseQuery(query, out var parsed));
        Assert.NotNull(parsed);

        var response = (byte[])query.Clone();
        response[2] |= 0x80;
        Assert.True(DnsProtocol.IsMatchingResponse(query, parsed!.QuestionEnd, response));

        var wrongId = (byte[])response.Clone();
        wrongId[0] ^= 0xFF;
        Assert.False(DnsProtocol.IsMatchingResponse(query, parsed.QuestionEnd, wrongId));

        var wrongQuestion = (byte[])response.Clone();
        wrongQuestion[13] ^= 0x01;
        Assert.False(DnsProtocol.IsMatchingResponse(query, parsed.QuestionEnd, wrongQuestion));

        var truncated = response.AsSpan(0, parsed.QuestionEnd - 1);
        Assert.False(DnsProtocol.IsMatchingResponse(query, parsed.QuestionEnd, truncated));

        // A reflected query (QR=0) or mismatched QDCOUNT must be rejected even if ID and question match.
        Assert.False(DnsProtocol.IsMatchingResponse(query, parsed.QuestionEnd, query));
        var zeroQuestions = (byte[])response.Clone();
        zeroQuestions[4] = 0;
        zeroQuestions[5] = 0;
        Assert.False(DnsProtocol.IsMatchingResponse(query, parsed.QuestionEnd, zeroQuestions));
    }

    [Fact]
    public void Shared_parser_upgrades_known_public_ips_and_parses_doh_urls()
    {
        Assert.True(DnsUpstream.TryParseTarget("1.1.1.1", out var cf));
        Assert.NotNull(cf);
        Assert.True(cf!.IsDoh);
        Assert.Equal("https://1.1.1.1/dns-query", cf.DohUri!.ToString());
        Assert.Equal(IPAddress.Parse("1.1.1.1"), cf.BootstrapAddress);
        Assert.False(cf.FallbackToPlainAllowed);

        Assert.True(DnsUpstream.TryParseTarget("https://cloudflare-dns.com/dns-query", out var named));
        Assert.NotNull(named);
        Assert.True(named!.IsDoh);
        Assert.Equal(IPAddress.Parse("1.1.1.1"), named.BootstrapAddress);

        Assert.True(DnsUpstream.TryParseTarget("192.168.0.1", out var lan));
        Assert.NotNull(lan);
        Assert.False(lan!.IsDoh);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("192.168.0.1"), 53), lan.PlainEndpoint);

        Assert.True(DnsUpstream.TryParseTarget("udp://1.1.1.1", out var forcedPlain));
        Assert.NotNull(forcedPlain);
        Assert.False(forcedPlain!.IsDoh);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53), forcedPlain.PlainEndpoint);

        Assert.False(DnsUpstream.TryParseTarget("https://127.0.0.1/dns-query", out _));
        Assert.False(DnsUpstream.TryParseTarget("https://localhost/dns-query", out _));
    }

    [Fact]
    public async Task Proxy_forwards_allowed_queries_over_doh_rfc8484()
    {
        byte[]? capturedWire = null;
        HttpMethod? capturedMethod = null;
        string? capturedContentType = null;
        using var dohHandler = new FakeDohHandler(req =>
        {
            capturedMethod = req.Method;
            capturedContentType = req.Content?.Headers.ContentType?.MediaType;
            capturedWire = req.Content!.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            var reply = DnsProtocol.BuildResponse(capturedWire, capturedWire.Length, 0);
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(reply),
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
            return response;
        });

        var target = new DnsUpstreamTarget(
            PlainEndpoint: null,
            DohUri: new Uri("https://1.1.1.1/dns-query"),
            BootstrapAddress: IPAddress.Parse("1.1.1.1"),
            FallbackToPlainAllowed: false);
        var settings = new PrivacyShieldSettings { Categories = PrivacyCategory.None };
        var policy = PrivacyShieldPolicy.Create(settings);
        await using var server = new DnsProxyServer(
            policy,
            [target],
            port: 0,
            dohHandler: dohHandler);

        var query = BuildQuery("allowed.example");
        using var client = new UdpClient(AddressFamily.InterNetwork);
        client.Connect(IPAddress.Loopback, server.Port);
        await client.SendAsync(query, query.Length);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var forwarded = await client.ReceiveAsync(timeout.Token);

        Assert.Equal(HttpMethod.Post, capturedMethod);
        Assert.Equal("application/dns-message", capturedContentType);
        Assert.NotNull(capturedWire);
        Assert.Equal(0, capturedWire![0]);
        Assert.Equal(0, capturedWire[1]);
        Assert.Equal(query[0], forwarded.Buffer[0]);
        Assert.Equal(query[1], forwarded.Buffer[1]);
        Assert.Equal(0, forwarded.Buffer[3] & 0x0F);

        var snapshot = server.Snapshot(settings);
        Assert.Equal(1, snapshot.Allowed);
        Assert.Contains("(DoH)", snapshot.Upstream, StringComparison.Ordinal);
        Assert.Contains("encrypted with DoH", snapshot.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://1.1.1.1/dns-query")]
    [InlineData("https://10.0.2.15:8443/dns-query")]
    public async Task Snapshot_detail_does_not_name_a_fixed_doh_port(string dohUrl)
    {
        // GUI/TEXT-LOW: a custom DoH port must not be reported as 443.
        await using var server = new DnsProxyServer(
            PrivacyShieldPolicy.Create(new PrivacyShieldSettings { Categories = PrivacyCategory.None }),
            [new DnsUpstreamTarget(PlainEndpoint: null, DohUri: new Uri(dohUrl))],
            port: 0);

        var snapshot = server.Snapshot(new PrivacyShieldSettings());

        Assert.Contains("encrypted with DoH", snapshot.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("443", snapshot.Detail, StringComparison.Ordinal);
        Assert.Contains("(DoH)", snapshot.Upstream, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Snapshot_detail_reports_plain_dns_without_a_doh_claim()
    {
        await using var server = new DnsProxyServer(
            PrivacyShieldPolicy.Create(new PrivacyShieldSettings { Categories = PrivacyCategory.None }),
            [new IPEndPoint(IPAddress.Loopback, 53)],
            port: 0);

        var snapshot = server.Snapshot(new PrivacyShieldSettings());

        Assert.Contains("plain UDP/TCP DNS", snapshot.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("encrypted with DoH", snapshot.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("prefer DoH", snapshot.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Proxy_does_not_downgrade_doh_failure_to_plaintext()
    {
        using var plainSink = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var plainPort = ((IPEndPoint)plainSink.Client.LocalEndPoint!).Port;
        using var failingDoh = new FakeDohHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));

        var target = new DnsUpstreamTarget(
            PlainEndpoint: new IPEndPoint(IPAddress.Loopback, plainPort),
            DohUri: new Uri("https://1.1.1.1/dns-query"),
            BootstrapAddress: IPAddress.Parse("1.1.1.1"),
            FallbackToPlainAllowed: false);
        var settings = new PrivacyShieldSettings { Categories = PrivacyCategory.None };
        var policy = PrivacyShieldPolicy.Create(settings);
        await using var server = new DnsProxyServer(
            policy,
            [target],
            port: 0,
            dohHandler: failingDoh);

        var query = BuildQuery("allowed.example");
        using var client = new UdpClient(AddressFamily.InterNetwork);
        client.Connect(IPAddress.Loopback, server.Port);
        await client.SendAsync(query, query.Length);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var reply = await client.ReceiveAsync(timeout.Token);

        Assert.Equal(2, reply.Buffer[3] & 0x0F);
        Assert.Equal(0, plainSink.Available);
        Assert.Equal(1, server.Snapshot(settings).Errors);
    }

    [Fact]
    public void Shared_parser_reads_redundant_doh_targets_and_the_default_doh_pair()
    {
        Assert.True(DnsUpstream.TryParseTargets("1.1.1.1, 9.9.9.9", out var parsed));
        Assert.Equal(2, parsed.Count);
        Assert.All(parsed, target =>
        {
            Assert.True(target.IsDoh);
            Assert.False(target.FallbackToPlainAllowed);
        });
        Assert.Equal("https://1.1.1.1/dns-query", parsed[0].DohUri!.ToString());
        Assert.Equal("https://9.9.9.9/dns-query", parsed[1].DohUri!.ToString());

        Assert.False(DnsUpstream.TryParseTargets("1.1.1.1, 127.0.0.1", out _));

        var defaults = DnsUpstream.DefaultDohTargets();
        Assert.Equal(2, defaults.Count);
        Assert.True(defaults.All(item => item.IsDoh && !item.FallbackToPlainAllowed));
    }

    [Fact]
    public async Task Proxy_survives_throwing_blocked_callback_and_stalled_tcp_client()
    {
        var settings = new PrivacyShieldSettings
        {
            Categories = PrivacyCategory.None,
            BlockedDomains = ["blocked.example"],
        };
        var policy = PrivacyShieldPolicy.Create(settings);
        await using var server = await CreateTcpCapableServerAsync(
            policy,
            _ => throw new InvalidOperationException("simulated history store fault"));

        // Connect a TCP client that sends 1 byte and stalls without closing.
        using var stalledTcp = new TcpClient(AddressFamily.InterNetwork);
        await stalledTcp.ConnectAsync(IPAddress.Loopback, server.Port);
        await stalledTcp.GetStream().WriteAsync(new byte[] { 0x00 });

        // UDP blocking must still answer NXDOMAIN cleanly despite throwing callback and stalled TCP client.
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Connect(IPAddress.Loopback, server.Port);
        var query = BuildQuery("blocked.example");
        await udp.SendAsync(query, query.Length);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var reply = await udp.ReceiveAsync(timeout.Token);
        Assert.Equal(3, reply.Buffer[3] & 0x0F);
    }

    [Fact]
    public async Task Proxy_updates_doh_bootstrap_map_when_targets_change()
    {
        using var handler = new FakeDohHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var initial = new DnsUpstreamTarget(
            PlainEndpoint: null,
            DohUri: new Uri("https://initial.example/dns-query"),
            BootstrapAddress: IPAddress.Parse("192.0.2.1"));
        var updated = new DnsUpstreamTarget(
            PlainEndpoint: null,
            DohUri: new Uri("https://updated.example/dns-query"),
            BootstrapAddress: IPAddress.Parse("198.51.100.2"));

        await using var server = new DnsProxyServer(
            PrivacyShieldPolicy.Create(new PrivacyShieldSettings { Categories = PrivacyCategory.None }),
            [initial],
            port: 0,
            dohHandler: handler);

        server.UpdateTargets([updated]);

        Assert.Single(server.Targets);
        Assert.Equal(IPAddress.Parse("198.51.100.2"), server.Targets[0].BootstrapAddress);
    }

    private sealed class FakeDohHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }

    private static byte[] BuildQuery(string domain)
    {
        var labels = domain.Split('.');
        var length = 12 + labels.Sum(label => label.Length + 1) + 1 + 4;
        var query = new byte[length];
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(0, 2), 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(4, 2), 1);

        var offset = 12;
        foreach (var label in labels)
        {
            query[offset++] = (byte)label.Length;
            Encoding.ASCII.GetBytes(label).CopyTo(query, offset);
            offset += label.Length;
        }

        query[offset++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(offset, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(offset + 2, 2), 1);
        return query;
    }
}
