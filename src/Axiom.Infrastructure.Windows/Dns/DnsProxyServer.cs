// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Axiom.Contracts.Privacy;
using Axiom.Contracts.Threat;
using Axiom.Infrastructure.Windows.IpHelper;

namespace Axiom.Infrastructure.Windows.Dns;

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

    private readonly TcpListener? _tcp4;

    private readonly TcpListener? _tcp6;

    private readonly PrivacyShieldPolicy _policy;

    private readonly IReadOnlyList<IPEndPoint> _upstreams;

    private readonly Action<PrivacyShieldBlockedEvent>? _onBlocked;

    private readonly CancellationTokenSource _cancellation = new();

    private readonly Task _loop4;

    private readonly Task? _loop6;

    private readonly Task? _tcpLoop4;

    private readonly Task? _tcpLoop6;

    private readonly ConcurrentDictionary<string, long> _blockedDomains =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentQueue<PrivacyShieldBlockedEvent> _recentBlocked = new();

    private static readonly ConcurrentDictionary<int, CachedAppIdentity> AppCache = new();
    private static readonly TimeSpan AppCacheLifetime = TimeSpan.FromSeconds(30);

    private long _queries;

    private long _allowed;

    private long _blocked;

    private long _errors;

    public DnsProxyServer(
        PrivacyShieldPolicy policy,
        IReadOnlyList<IPEndPoint> upstreams,
        int port,
        Action<PrivacyShieldBlockedEvent>? onBlocked = null)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _upstreams = upstreams ?? throw new ArgumentNullException(nameof(upstreams));
        _onBlocked = onBlocked;
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
            RecentBlocked = _recentBlocked
                .ToArray()
                .Reverse()
                .Take(50)
                .ToArray(),
            Detail = $"Resolved {Interlocked.Read(ref _allowed)} and blocked {Interlocked.Read(ref _blocked)} queries. " +
                     "DNS filtering is not complete traffic filtering; DoH/DoT/DoQ and hardcoded IPs bypass it.",
        };
    }

    public async ValueTask DisposeAsync()
    {
        await _cancellation.CancelAsync().ConfigureAwait(false);
        _udp4.Dispose();
        _udp6?.Dispose();
        _tcp4?.Stop();
        _tcp6?.Stop();

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
                        decision.Category,
                        client.Client.RemoteEndPoint as IPEndPoint,
                        tcp: true);
                    response = DnsProtocol.BuildResponse(query, parsed.QuestionEnd, 3);
                }
                else
                {
                    var forwarded = await ForwardTcpAsync(query, cancellationToken).ConfigureAwait(false);
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
            catch (Exception exception) when (exception is
                         IOException or SocketException or OperationCanceledException or ObjectDisposedException)
            {
                Interlocked.Increment(ref _errors);
            }
        }
    }

    private async Task<byte[]?> ForwardTcpAsync(byte[] query, CancellationToken cancellationToken)
    {
        foreach (var upstream in _upstreams)
        {
            try
            {
                using var client = new TcpClient(upstream.AddressFamily);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(UpstreamTimeout);
                await client.ConnectAsync(upstream, timeout.Token).ConfigureAwait(false);

                using var stream = client.GetStream();
                await WriteTcpAsync(stream, query, timeout.Token).ConfigureAwait(false);
                var lengthBytes = await ReadExactAsync(stream, 2, timeout.Token).ConfigureAwait(false);
                if (lengthBytes is null)
                {
                    continue;
                }

                var length = (lengthBytes[0] << 8) | lengthBytes[1];
                if (length is <= 0 or > MaxUpstreamResponseBytes)
                {
                    continue;
                }

                var response = await ReadExactAsync(stream, length, timeout.Token).ConfigureAwait(false);
                if (response is not null)
                {
                    return response;
                }
            }
            catch (Exception exception) when (exception is
                         IOException or SocketException or OperationCanceledException or ObjectDisposedException)
            {
                // Try the next upstream.
            }
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
            RecordBlocked(parsed.Domain, decision.Category, request.RemoteEndPoint, tcp: false);
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

    private void RecordBlocked(
        string domain,
        PrivacyCategory category,
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
            category,
            DateTimeOffset.UtcNow)
        {
            AppName = app.Name,
            AppPath = app.Path,
            AgentName = app.AgentName,
            AgentPath = app.AgentPath,
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

    private static (string Name, string Path, string AgentName, string AgentPath) ResolveApp(
        IPEndPoint? source,
        bool tcp)
    {
        if (source is null || source.Port <= 0)
        {
            return (string.Empty, string.Empty, string.Empty, string.Empty);
        }

        var processId = FindOwningProcess(source, tcp);
        if (processId <= 4)
        {
            return (string.Empty, string.Empty, string.Empty, string.Empty);
        }

        var now = DateTimeOffset.UtcNow;
        if (AppCache.TryGetValue(processId, out var cached) &&
            now - cached.ResolvedUtc < AppCacheLifetime)
        {
            return (cached.Name, cached.Path, cached.AgentName, cached.AgentPath);
        }

        var name = string.Empty;
        var path = string.Empty;
        try
        {
            using var process = Process.GetProcessById(processId);
            name = process.ProcessName + ".exe";
            try
            {
                path = process.MainModule?.FileName ?? string.Empty;
            }
            catch (Exception exception) when (exception is
                         System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
            {
                // Protected or exiting process; the name is still useful.
            }
        }
        catch (Exception exception) when (exception is
                     ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
        }

        // Agents usually fetch through a tool process (curl, git, nslookup), so the querying process
        // is not the agent itself. Walk the parent chain once per process (cached) and remember the
        // nearest agent ancestor; that is what makes "fetched by tool" provable.
        var (agentName, agentPath) = FindAgentAncestor(processId);

        AppCache[processId] = new CachedAppIdentity(name, path, agentName, agentPath, now);
        if (AppCache.Count > 256)
        {
            foreach (var pair in AppCache)
            {
                if (now - pair.Value.ResolvedUtc > AppCacheLifetime)
                {
                    AppCache.TryRemove(pair.Key, out _);
                }
            }
        }

        return (name, path, agentName, agentPath);
    }

    private static (string Name, string Path) FindAgentAncestor(int processId)
    {
        var current = processId;
        for (var depth = 0; depth < 6 && current > 4; depth++)
        {
            var parent = ParentProcessId(current);
            if (parent <= 4 || parent == current)
            {
                return (string.Empty, string.Empty);
            }

            try
            {
                using var process = Process.GetProcessById(parent);
                var name = process.ProcessName + ".exe";
                var path = string.Empty;
                try
                {
                    path = process.MainModule?.FileName ?? string.Empty;
                }
                catch (Exception exception) when (exception is
                             System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
                {
                }

                if (AgentProcessMatcher.IsAgentProcess(name, path))
                {
                    return (name, path);
                }
            }
            catch (Exception exception) when (exception is
                         ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // Exited or protected parent; keep walking with the pid we have.
            }

            current = parent;
        }

        return (string.Empty, string.Empty);
    }

    private static int ParentProcessId(int processId)
    {
        var snapshot = CreateToolhelp32Snapshot(Th32CsSnapProcess, 0);
        if (snapshot == IntPtr.Zero || snapshot == InvalidHandleValue)
        {
            return 0;
        }

        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32First(snapshot, ref entry))
            {
                return 0;
            }

            do
            {
                if (entry.ProcessId == (uint)processId)
                {
                    return (int)entry.ParentProcessId;
                }

                entry.Size = (uint)Marshal.SizeOf<ProcessEntry32>();
            }
            while (Process32Next(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return 0;
    }

    private const uint Th32CsSnapProcess = 0x00000002;

    private static readonly IntPtr InvalidHandleValue = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private static int FindOwningProcess(IPEndPoint source, bool tcp)
    {
        try
        {
            if (tcp)
            {
                if (source.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    return NativeMethods.QueryTcpV6()
                        .Where(row => EndpointFormatter.HostPort(row.LocalPort) == source.Port &&
                                      row.State == 5 &&
                                      row.OwningPid > 4)
                        .Select(row => (int)row.OwningPid)
                        .FirstOrDefault();
                }

                return NativeMethods.QueryTcpV4()
                    .Where(row => EndpointFormatter.HostPort(row.LocalPort) == source.Port &&
                                  row.State == 5 &&
                                  row.OwningPid > 4)
                    .Select(row => (int)row.OwningPid)
                    .FirstOrDefault();
            }

            if (source.AddressFamily == AddressFamily.InterNetworkV6)
            {
                return NativeMethods.QueryUdpV6()
                    .Where(row => EndpointFormatter.HostPort(row.LocalPort) == source.Port &&
                                  row.OwningPid > 4)
                    .Select(row => (int)row.OwningPid)
                    .FirstOrDefault();
            }

            return NativeMethods.QueryUdpV4()
                .Where(row => EndpointFormatter.HostPort(row.LocalPort) == source.Port &&
                              row.OwningPid > 4)
                .Select(row => (int)row.OwningPid)
                .FirstOrDefault();
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return 0;
        }
    }

    private sealed record CachedAppIdentity(
        string Name,
        string Path,
        string AgentName,
        string AgentPath,
        DateTimeOffset ResolvedUtc);
}
