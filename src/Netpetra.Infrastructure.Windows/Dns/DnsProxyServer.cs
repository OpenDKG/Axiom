// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Netpetra.Contracts.Privacy;

namespace Netpetra.Infrastructure.Windows.Dns;

/// <summary>
/// Small loopback DNS filter used by the opt-in Privacy Shield module. It evaluates only the
/// question name, forwards allowed queries to the configured upstream and never changes Windows
/// adapter settings itself.
/// </summary>
public sealed class DnsProxyServer : IAsyncDisposable
{
    private const int MaxUpstreamResponseBytes = 4096;

    private static readonly TimeSpan UpstreamTimeout = TimeSpan.FromSeconds(3);

    private readonly UdpClient _udp4;

    private readonly UdpClient? _udp6;

    private readonly PrivacyShieldPolicy _policy;

    private readonly IReadOnlyList<IPEndPoint> _upstreams;

    private readonly CancellationTokenSource _cancellation = new();

    private readonly Task _loop4;

    private readonly Task? _loop6;

    private readonly ConcurrentDictionary<string, long> _blockedDomains =
        new(StringComparer.OrdinalIgnoreCase);

    private long _queries;

    private long _allowed;

    private long _blocked;

    private long _errors;

    public DnsProxyServer(
        PrivacyShieldPolicy policy,
        IReadOnlyList<IPEndPoint> upstreams,
        int port)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _upstreams = upstreams ?? throw new ArgumentNullException(nameof(upstreams));
        if (upstreams.Count == 0)
        {
            throw new ArgumentException("At least one upstream DNS endpoint is required.", nameof(upstreams));
        }

        _udp4 = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
        Port = ((IPEndPoint)_udp4.Client.LocalEndPoint!).Port;

        try
        {
            _udp6 = new UdpClient(new IPEndPoint(IPAddress.IPv6Loopback, Port));
        }
        catch (SocketException)
        {
            _udp6 = null;
        }

        _loop4 = ReceiveLoopAsync(_udp4, _cancellation.Token);
        _loop6 = _udp6 is null ? null : ReceiveLoopAsync(_udp6, _cancellation.Token);
    }

    public int Port { get; }

    public string BindAddress => _udp6 is null ? "127.0.0.1" : "127.0.0.1, ::1";

    public string Upstream => string.Join(", ", _upstreams.Select(endpoint => endpoint.ToString()));

    public PrivacyShieldStatus Snapshot(PrivacyShieldSettings settings)
    {
        var top = _blockedDomains
            .OrderByDescending(pair => pair.Value)
            .ThenBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .Select(pair => new PrivacyShieldTopDomain(pair.Key, pair.Value))
            .ToArray();

        return new PrivacyShieldStatus
        {
            State = "Active",
            Enabled = true,
            Running = true,
            Port = Port,
            BindAddress = BindAddress,
            Upstream = Upstream,
            Queries = Interlocked.Read(ref _queries),
            Allowed = Interlocked.Read(ref _allowed),
            Blocked = Interlocked.Read(ref _blocked),
            Errors = Interlocked.Read(ref _errors),
            RuleCount = _policy.RuleCount,
            TopBlocked = top,
            Detail = $"Resolved {Interlocked.Read(ref _allowed)} and blocked {Interlocked.Read(ref _blocked)} queries. " +
                     "DNS filtering is not complete traffic filtering; DoH/DoT/DoQ and hardcoded IPs bypass it.",
        };
    }

    public async ValueTask DisposeAsync()
    {
        await _cancellation.CancelAsync().ConfigureAwait(false);
        _udp4.Dispose();
        _udp6?.Dispose();

        try
        {
            await _loop4.ConfigureAwait(false);
            if (_loop6 is not null)
            {
                await _loop6.ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }

        _cancellation.Dispose();
    }

    private async Task ReceiveLoopAsync(UdpClient client, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            UdpReceiveResult request;
            try
            {
                request = await client.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException)
            {
                Interlocked.Increment(ref _errors);
                continue;
            }

            _ = HandleQueryAsync(client, request, cancellationToken);
        }
    }

    private async Task HandleQueryAsync(
        UdpClient client,
        UdpReceiveResult request,
        CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _queries);
        var query = request.Buffer;

        if (query.Length == 0 || query.Length > DnsProtocol.MaxQueryBytes)
        {
            Interlocked.Increment(ref _errors);
            return;
        }

        if (!DnsProtocol.TryParseQuery(query, out var parsed) || parsed is null)
        {
            Interlocked.Increment(ref _errors);
            await SendAsync(client, DnsProtocol.BuildError(query, 1), request.RemoteEndPoint).ConfigureAwait(false);
            return;
        }

        var decision = _policy.Evaluate(parsed.Domain);
        if (decision.Blocked)
        {
            Interlocked.Increment(ref _blocked);
            RecordBlocked(parsed.Domain);
            await SendAsync(
                client,
                DnsProtocol.BuildResponse(query, parsed.QuestionEnd, 3),
                request.RemoteEndPoint).ConfigureAwait(false);
            return;
        }

        var upstreamResponse = await ForwardAsync(query, cancellationToken).ConfigureAwait(false);
        if (upstreamResponse is null)
        {
            Interlocked.Increment(ref _errors);
            await SendAsync(
                client,
                DnsProtocol.BuildResponse(query, parsed.QuestionEnd, 2),
                request.RemoteEndPoint).ConfigureAwait(false);
            return;
        }

        Interlocked.Increment(ref _allowed);
        await SendAsync(client, upstreamResponse, request.RemoteEndPoint).ConfigureAwait(false);
    }

    private async Task<byte[]?> ForwardAsync(byte[] query, CancellationToken cancellationToken)
    {
        foreach (var upstream in _upstreams)
        {
            try
            {
                using var socket = new Socket(
                    upstream.AddressFamily,
                    SocketType.Dgram,
                    ProtocolType.Udp);
                await socket.ConnectAsync(upstream, cancellationToken).ConfigureAwait(false);
                await socket.SendAsync(query, SocketFlags.None, cancellationToken).ConfigureAwait(false);

                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(UpstreamTimeout);
                var response = new byte[MaxUpstreamResponseBytes];
                var received = await socket
                    .ReceiveAsync(response.AsMemory(), SocketFlags.None, timeout.Token)
                    .ConfigureAwait(false);
                if (received > 0)
                {
                    return response[..received];
                }
            }
            catch (Exception exception) when (exception is
                         SocketException or OperationCanceledException or ObjectDisposedException)
            {
                // Try the next configured upstream.
            }
        }

        return null;
    }

    private static async Task SendAsync(UdpClient client, byte[] response, IPEndPoint remote)
    {
        if (response.Length == 0)
        {
            return;
        }

        try
        {
            await client.SendAsync(response, response.Length, remote).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is SocketException or ObjectDisposedException)
        {
        }
    }

    private void RecordBlocked(string domain)
    {
        if (_blockedDomains.Count >= 256 && !_blockedDomains.ContainsKey(domain))
        {
            return;
        }

        _blockedDomains.AddOrUpdate(domain, 1, (_, count) => count + 1);
    }
}
