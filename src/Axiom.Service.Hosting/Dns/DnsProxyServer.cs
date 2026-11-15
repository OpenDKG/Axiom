// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using Axiom.Contracts.Privacy;

namespace Axiom.Service.Hosting.Dns;

/// <summary>
/// Small loopback DNS filter used by the opt-in Privacy Shield module. It evaluates only the
/// question name, forwards allowed queries to the configured upstream and never changes the
/// system DNS configuration itself (that is the job of <see cref="IPrivacyDnsPlatform"/>).
/// Attribution of a blocked query to the querying app goes through <see cref="IDnsAppAttributor"/>.
/// </summary>
public sealed class DnsProxyServer : IAsyncDisposable
{
    private const int MaxUpstreamResponseBytes = 4096;

    private static readonly TimeSpan UpstreamTimeout = TimeSpan.FromSeconds(3);

    private static readonly TimeSpan MultiTargetAttemptTimeout = TimeSpan.FromMilliseconds(1500);

    private readonly UdpClient _udp4;

    private readonly UdpClient? _udp6;

    private readonly TcpListener? _tcp4;

    private readonly TcpListener? _tcp6;

    private readonly PrivacyShieldPolicy _policy;

    // Swapped as a whole by UpdateTargets; forwarders read it once per query.
    private volatile IReadOnlyList<DnsUpstreamTarget> _targets;

    // Created when the first DoH target appears (constructor or a later swap).
    private volatile HttpClient? _httpClient;

    private readonly HttpMessageHandler? _dohHandler;

    private readonly Action<PrivacyShieldBlockedEvent>? _onBlocked;

    private readonly CancellationTokenSource _cancellation = new();

    private readonly Task _loop4;

    private readonly Task? _loop6;

    private readonly Task? _tcpLoop4;

    private readonly Task? _tcpLoop6;

    private readonly ConcurrentDictionary<string, long> _blockedDomains =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentQueue<PrivacyShieldBlockedEvent> _recentBlocked = new();

    private readonly IDnsAppAttributor? _attributor;

    private long _queries;

    private long _allowed;

    private long _blocked;

    private long _errors;

    private long _upstreamFailureStreak;

    public DnsProxyServer(
        PrivacyShieldPolicy policy,
        IReadOnlyList<IPEndPoint> upstreams,
        int port,
        Action<PrivacyShieldBlockedEvent>? onBlocked = null,
        IDnsAppAttributor? attributor = null)
        : this(
            policy,
            (upstreams ?? throw new ArgumentNullException(nameof(upstreams)))
                .Select(endpoint => new DnsUpstreamTarget(endpoint))
                .ToArray(),
            port,
            onBlocked,
            dohHandler: null,
            attributor)
    {
    }

    public DnsProxyServer(
        PrivacyShieldPolicy policy,
        IReadOnlyList<DnsUpstreamTarget> targets,
        int port,
        Action<PrivacyShieldBlockedEvent>? onBlocked = null,
        HttpMessageHandler? dohHandler = null,
        IDnsAppAttributor? attributor = null)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _targets = targets ?? throw new ArgumentNullException(nameof(targets));
        _onBlocked = onBlocked;
        _attributor = attributor;
        _dohHandler = dohHandler;
        ValidateTargets(targets);
        EnsureDohClient(targets);

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

        try
        {
            _tcp4 = new TcpListener(IPAddress.Loopback, Port);
            _tcp4.Start();
        }
        catch (SocketException)
        {
            _tcp4 = null;
        }

        try
        {
            _tcp6 = new TcpListener(IPAddress.IPv6Loopback, Port);
            _tcp6.Start();
        }
        catch (SocketException)
        {
            _tcp6 = null;
        }

        _loop4 = ReceiveLoopAsync(_udp4, _cancellation.Token);
        _loop6 = _udp6 is null ? null : ReceiveLoopAsync(_udp6, _cancellation.Token);
        _tcpLoop4 = _tcp4 is null ? null : AcceptLoopAsync(_tcp4, _cancellation.Token);
        _tcpLoop6 = _tcp6 is null ? null : AcceptLoopAsync(_tcp6, _cancellation.Token);
    }

    public int Port { get; }

    public string BindAddress
    {
        get
        {
            var address = _udp6 is null ? "127.0.0.1" : "127.0.0.1, ::1";
            return _tcp4 is null && _tcp6 is null ? address + " (UDP only)" : address;
        }
    }

    public string Upstream => string.Join(", ", _targets.Select(target => target.DisplayText));

    /// <summary>The plain endpoints of the upstreams in use right now (snapshot).</summary>
    public IReadOnlyList<IPEndPoint> Upstreams => _targets
        .Where(target => target.PlainEndpoint is not null)
        .Select(target => target.PlainEndpoint!)
        .ToArray();

    /// <summary>The upstream targets in use right now (snapshot).</summary>
    public IReadOnlyList<DnsUpstreamTarget> Targets => _targets;

    /// <summary>
    /// Consecutive allowed queries that no upstream answered; reset by the next answered query.
    /// A growing streak means the upstreams are gone (network change), not that a domain is bad.
    /// </summary>
    public long UpstreamFailureStreak => Interlocked.Read(ref _upstreamFailureStreak);

    /// <summary>
    /// Replaces the upstream list with plain UDP/TCP endpoints without touching the listeners
    /// (same meaning as the endpoint constructor: no DoH upgrade).
    /// </summary>
    public void UpdateUpstreams(IReadOnlyList<IPEndPoint> upstreams)
    {
        ArgumentNullException.ThrowIfNull(upstreams);
        if (upstreams.Count == 0)
        {
            throw new ArgumentException("At least one upstream DNS endpoint is required.", nameof(upstreams));
        }

        UpdateTargets(upstreams.Select(endpoint => new DnsUpstreamTarget(endpoint)).ToArray());
    }

    /// <summary>
    /// Replaces the upstream targets without touching the listeners (used when the system
    /// resolvers change while Privacy Shield is on). Queries in flight finish against the old list.
    /// </summary>
    public void UpdateTargets(IReadOnlyList<DnsUpstreamTarget> targets)
    {
        ValidateTargets(targets);
        var copy = targets.ToArray();
        EnsureDohClient(copy);
        _targets = copy;
        Interlocked.Exchange(ref _upstreamFailureStreak, 0);
    }

    private static void ValidateTargets(IReadOnlyList<DnsUpstreamTarget> targets)
    {
        if (targets.Count == 0)
        {
            throw new ArgumentException("At least one upstream DNS target is required.", nameof(targets));
        }

        if (targets.Any(target => target is null || (!target.IsDoh && target.PlainEndpoint is null)))
        {
            throw new ArgumentException("Every upstream DNS target must specify a DoH URI or IP endpoint.", nameof(targets));
        }
    }

    private void EnsureDohClient(IReadOnlyList<DnsUpstreamTarget> targets)
    {
        if (_httpClient is null && targets.Any(target => target.IsDoh))
        {
            _httpClient = _dohHandler is not null
                ? new HttpClient(_dohHandler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan }
                : CreateDohHttpClient(targets);
        }
    }

    private void NoteForwardResult(bool answered)
    {
        if (answered)
        {
            Interlocked.Exchange(ref _upstreamFailureStreak, 0);
        }
        else
        {
            Interlocked.Increment(ref _upstreamFailureStreak);
        }
    }

    public PrivacyShieldStatus Snapshot(PrivacyShieldSettings settings)
    {
        var top = _blockedDomains
            .OrderByDescending(pair => pair.Value)
            .ThenBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .Select(pair => new PrivacyShieldTopDomain(pair.Key, pair.Value))
            .ToArray();

        var allDoh = _targets.All(target => target.IsDoh);
        var anyDoh = _targets.Any(target => target.IsDoh);
        var transportNote = allDoh
            ? "Outbound queries are encrypted with DoH (HTTPS/443)."
            : anyDoh
                ? "Outbound queries prefer DoH (HTTPS/443); non-DoH upstreams remain plain DNS."
                : "Outbound queries use plain UDP/TCP DNS.";

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
            RecentBlocked = _recentBlocked
                .ToArray()
                .Reverse()
                .Take(50)
                .ToArray(),
            Detail = $"Resolved {Interlocked.Read(ref _allowed)} and blocked {Interlocked.Read(ref _blocked)} queries. " +
                     $"{transportNote} " +
                     "DNS filtering is not complete traffic filtering; DoH/DoT/DoQ and hardcoded IPs bypass local filtering.",
        };
    }

    public async ValueTask DisposeAsync()
    {
        await _cancellation.CancelAsync().ConfigureAwait(false);
        _udp4.Dispose();
        _udp6?.Dispose();
        _tcp4?.Stop();
        _tcp6?.Stop();
        _httpClient?.Dispose();

        try
        {
            await _loop4.ConfigureAwait(false);
            if (_loop6 is not null)
            {
                await _loop6.ConfigureAwait(false);
            }

            if (_tcpLoop4 is not null)
            {
                await _tcpLoop4.ConfigureAwait(false);
            }

            if (_tcpLoop6 is not null)
            {
                await _tcpLoop6.ConfigureAwait(false);
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

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
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

            _ = HandleTcpClientAsync(client, cancellationToken);
        }
    }

    private async Task HandleTcpClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        var queryReceived = false;
        using (client)
        using (var stream = client.GetStream())
        {
            try
            {
                var lengthBytes = await ReadExactAsync(stream, 2, cancellationToken).ConfigureAwait(false);
                if (lengthBytes is null)
                {
                    return;
                }

                var length = (lengthBytes[0] << 8) | lengthBytes[1];
                if (length is <= 0 or > DnsProtocol.MaxQueryBytes)
                {
                    Interlocked.Increment(ref _errors);
                    return;
                }

                var query = await ReadExactAsync(stream, length, cancellationToken).ConfigureAwait(false);
                if (query is null)
                {
                    return;
                }

                queryReceived = true;
                Interlocked.Increment(ref _queries);
                if (!DnsProtocol.TryParseQuery(query, out var parsed) || parsed is null)
                {
                    Interlocked.Increment(ref _errors);
                    await WriteTcpAsync(stream, DnsProtocol.BuildError(query, 1), cancellationToken)
                        .ConfigureAwait(false);
                    return;
                }

                var decision = _policy.Evaluate(parsed.Domain);
                byte[] response;
                if (decision.Blocked)
                {
                    Interlocked.Increment(ref _blocked);
                    RecordBlocked(
                        parsed.Domain,
                        decision,
                        client.Client.RemoteEndPoint as IPEndPoint,
                        tcp: true);
                    response = DnsProtocol.BuildResponse(query, parsed.QuestionEnd, 3);
                }
                else
                {
                    var forwarded = await ForwardToTargetsAsync(
                        query,
                        parsed.QuestionEnd,
                        preferTcpForPlain: true,
                        cancellationToken).ConfigureAwait(false);
                    if (forwarded is null)
                    {
                        Interlocked.Increment(ref _errors);
                        response = DnsProtocol.BuildResponse(query, parsed.QuestionEnd, 2);
                    }
                    else
                    {
                        Interlocked.Increment(ref _allowed);
                        response = forwarded;
                    }
                }

                await WriteTcpAsync(stream, response, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (Exception exception) when (exception is
                         IOException or SocketException or OperationCanceledException or ObjectDisposedException)
            {
                if (queryReceived)
                {
                    Interlocked.Increment(ref _errors);
                }
            }
        }
    }

    private async Task<byte[]?> ForwardToTargetsAsync(
        byte[] query,
        int questionEnd,
        bool preferTcpForPlain,
        CancellationToken cancellationToken)
    {
        var response = await ForwardToTargetsCoreAsync(query, questionEnd, preferTcpForPlain, cancellationToken)
            .ConfigureAwait(false);
        NoteForwardResult(response is not null);
        return response;
    }

    private async Task<byte[]?> ForwardToTargetsCoreAsync(
        byte[] query,
        int questionEnd,
        bool preferTcpForPlain,
        CancellationToken cancellationToken)
    {
        var attemptTimeout = _targets.Count > 1 ? MultiTargetAttemptTimeout : UpstreamTimeout;
        foreach (var target in _targets)
        {
            if (target.IsDoh && target.DohUri is not null)
            {
                var dohResponse = await ForwardDohAsync(
                    target.DohUri,
                    query,
                    questionEnd,
                    attemptTimeout,
                    cancellationToken).ConfigureAwait(false);
                if (dohResponse is not null)
                {
                    return dohResponse;
                }

                if (!target.FallbackToPlainAllowed || target.PlainEndpoint is null)
                {
                    continue;
                }
            }

            if (target.PlainEndpoint is not null)
            {
                var plainResponse = preferTcpForPlain
                    ? await ForwardTcpEndpointAsync(target.PlainEndpoint, query, questionEnd, attemptTimeout, cancellationToken)
                        .ConfigureAwait(false)
                    : await ForwardUdpEndpointAsync(target.PlainEndpoint, query, questionEnd, attemptTimeout, cancellationToken)
                        .ConfigureAwait(false);
                if (plainResponse is not null)
                {
                    return plainResponse;
                }
            }
        }

        return null;
    }

    private async Task<byte[]?> ForwardDohAsync(
        Uri dohUri,
        byte[] query,
        int questionEnd,
        TimeSpan attemptTimeout,
        CancellationToken cancellationToken)
    {
        if (_httpClient is null)
        {
            return null;
        }

        var wireQuery = (byte[])query.Clone();
        // RFC 8484 §4.1: DoH wire messages use ID = 0; restore the client's original ID on return.
        wireQuery[0] = 0;
        wireQuery[1] = 0;

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, dohUri)
            {
                Version = HttpVersion.Version20,
                VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
                Content = new ByteArrayContent(wireQuery),
            };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(attemptTimeout);

            using var response = await _httpClient
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token)
                .ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            await using var body = await response.Content
                .ReadAsStreamAsync(timeout.Token)
                .ConfigureAwait(false);
            var buffer = await ReadBoundedAsync(body, MaxUpstreamResponseBytes, timeout.Token)
                .ConfigureAwait(false);
            if (buffer is null || buffer.Length < questionEnd)
            {
                return null;
            }

            buffer[0] = query[0];
            buffer[1] = query[1];
            return DnsProtocol.IsMatchingResponse(query, questionEnd, buffer)
                ? buffer
                : null;
        }
        catch (Exception exception) when (exception is
                     HttpRequestException or IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
            return null;
        }
    }

    private static async Task<byte[]?> ReadBoundedAsync(
        Stream stream,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[maxBytes + 1];
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream
                .ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                return buffer[..total];
            }

            total += read;
        }

        // Response exceeded MaxUpstreamResponseBytes.
        return null;
    }

    private static HttpClient CreateDohHttpClient(IReadOnlyList<DnsUpstreamTarget> targets)
    {
        var bootstrapByHost = new Dictionary<string, IPAddress>(StringComparer.OrdinalIgnoreCase);
        foreach (var target in targets)
        {
            if (target.DohUri is not null && target.BootstrapAddress is not null)
            {
                bootstrapByHost.TryAdd(target.DohUri.DnsSafeHost, target.BootstrapAddress);
            }
        }

        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            UseCookies = false,
            AllowAutoRedirect = false,
            ConnectTimeout = UpstreamTimeout,
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            ConnectCallback = async (context, cancellationToken) =>
            {
                var host = context.DnsEndPoint.Host;
                if (!bootstrapByHost.TryGetValue(host, out var bootstrapIp) &&
                    !DnsUpstream.TryResolveBootstrapAddress(host, out bootstrapIp))
                {
                    var addresses = await System.Net.Dns
                        .GetHostAddressesAsync(host, cancellationToken)
                        .ConfigureAwait(false);
                    bootstrapIp = addresses.FirstOrDefault(address => !IPAddress.IsLoopback(address));
                }

                if (bootstrapIp is null)
                {
                    throw new SocketException((int)SocketError.HostNotFound);
                }

                var socket = new Socket(bootstrapIp.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true,
                };
                try
                {
                    await socket
                        .ConnectAsync(new IPEndPoint(bootstrapIp, context.DnsEndPoint.Port), cancellationToken)
                        .ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };

        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = Timeout.InfiniteTimeSpan,
        };
    }

    private static async Task<byte[]?> ForwardTcpEndpointAsync(
        IPEndPoint upstream,
        byte[] query,
        int questionEnd,
        TimeSpan attemptTimeout,
        CancellationToken cancellationToken)
    {
        try
        {
            using var client = new TcpClient(upstream.AddressFamily);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(attemptTimeout);
            await client.ConnectAsync(upstream, timeout.Token).ConfigureAwait(false);

            using var stream = client.GetStream();
            await WriteTcpAsync(stream, query, timeout.Token).ConfigureAwait(false);
            var lengthBytes = await ReadExactAsync(stream, 2, timeout.Token).ConfigureAwait(false);
            if (lengthBytes is null)
            {
                return null;
            }

            var length = (lengthBytes[0] << 8) | lengthBytes[1];
            if (length is <= 0 or > MaxUpstreamResponseBytes)
            {
                return null;
            }

            var response = await ReadExactAsync(stream, length, timeout.Token).ConfigureAwait(false);
            if (response is not null && DnsProtocol.IsMatchingResponse(query, questionEnd, response))
            {
                return response;
            }
        }
        catch (Exception exception) when (exception is
                     IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
        }

        return null;
    }

    private static async Task WriteTcpAsync(
        Stream stream,
        byte[] response,
        CancellationToken cancellationToken)
    {
        var prefix = new byte[]
        {
            (byte)(response.Length >> 8),
            (byte)response.Length,
        };
        await stream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(response, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadExactAsync(
        Stream stream,
        int count,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }

            offset += read;
        }

        return buffer;
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
            RecordBlocked(parsed.Domain, decision, request.RemoteEndPoint, tcp: false);
            await SendAsync(
                client,
                DnsProtocol.BuildResponse(query, parsed.QuestionEnd, 3),
                request.RemoteEndPoint).ConfigureAwait(false);
            return;
        }

        var upstreamResponse = await ForwardToTargetsAsync(
            query,
            parsed.QuestionEnd,
            preferTcpForPlain: false,
            cancellationToken).ConfigureAwait(false);
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

    private static async Task<byte[]?> ForwardUdpEndpointAsync(
        IPEndPoint upstream,
        byte[] query,
        int questionEnd,
        TimeSpan attemptTimeout,
        CancellationToken cancellationToken)
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
            timeout.CancelAfter(attemptTimeout);
            var response = new byte[MaxUpstreamResponseBytes];
            var received = await socket
                .ReceiveAsync(response.AsMemory(), SocketFlags.None, timeout.Token)
                .ConfigureAwait(false);
            if (received > 0 && DnsProtocol.IsMatchingResponse(query, questionEnd, response.AsSpan(0, received)))
            {
                return response[..received];
            }
        }
        catch (Exception exception) when (exception is
                     SocketException or OperationCanceledException or ObjectDisposedException)
        {
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

    private void RecordBlocked(
        string domain,
        DnsPolicyDecision decision,
        IPEndPoint? source,
        bool tcp)
    {
        if (_blockedDomains.Count < 256 || _blockedDomains.ContainsKey(domain))
        {
            _blockedDomains.AddOrUpdate(domain, 1, (_, count) => count + 1);
        }

        var app = ResolveApp(source, tcp);
        var blocked = new PrivacyShieldBlockedEvent(
            domain,
            decision.Category,
            DateTimeOffset.UtcNow)
        {
            AppName = app.Name,
            AppPath = app.Path,
            AgentName = app.AgentName,
            AgentPath = app.AgentPath,
            MatchedRule = decision.MatchedRule ?? domain,
            SourceId = decision.SourceId,
            DetectionReason = "dns-blocklist-match",
            IsListDerived = decision.SourceId is not ("" or "starter" or "custom"),
            LookupBlocked = true,
        };
        _recentBlocked.Enqueue(blocked);
        while (_recentBlocked.Count > 50)
        {
            _recentBlocked.TryDequeue(out _);
        }

        try
        {
            _onBlocked?.Invoke(blocked);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // History persistence is best effort and must never fail a DNS response.
        }
    }

    private DnsAppIdentity ResolveApp(IPEndPoint? source, bool tcp)
    {
        if (_attributor is null || source is null || source.Port <= 0)
        {
            return DnsAppIdentity.Unknown;
        }

        try
        {
            return _attributor.Resolve(source, tcp) ?? DnsAppIdentity.Unknown;
        }
#pragma warning disable CA1031 // Attribution is best effort and must never fail a DNS response.
        catch (Exception)
#pragma warning restore CA1031
        {
            return DnsAppIdentity.Unknown;
        }
    }
}
