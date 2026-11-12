// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Axiom.Contracts.Privacy;
using Axiom.Service.Hosting.Dns;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

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

    [Fact]
    public async Task Proxy_blocks_matching_domains_over_tcp()
    {
        var settings = new PrivacyShieldSettings
        {
            Categories = PrivacyCategory.None,
            BlockedDomains = ["blocked.example"],
        };
        var policy = PrivacyShieldPolicy.Create(settings);
        await using var server = new DnsProxyServer(
            policy,
            [new IPEndPoint(IPAddress.Loopback, 9)],
            port: 0);

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
