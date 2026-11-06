// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Net;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.Windows.ProcessIdentity;

namespace Axiom.Infrastructure.Windows.IpHelper;

/// <summary>
/// Read-only TCP/UDP inventory from the Windows IP Helper owner tables (IPv4 and IPv6) with
/// process attribution. Runs without elevation; protected processes are reported as unresolved.
/// </summary>
public sealed class IpHelperConnectionSource : IConnectionSnapshotSource
{
    private static readonly TimeSpan NewConnectionWindow = TimeSpan.FromSeconds(60);

    private static readonly TimeSpan FirstSeenRetention = TimeSpan.FromMinutes(5);

    private static readonly string[] StaticLimitations =
    [
        "Byte counts are not exposed by the IP Helper tables; traffic measurement arrives with FND-004.",
        "Connections shorter than the poll interval can be missed; they are not reconstructed.",
        "The UDP owner table has no remote endpoint, so UDP peer and direction stay unknown.",
        "Rows with PID 0 are TIME_WAIT or kernel sockets without an owning process.",
        "TCP direction is inferred from listen state and local listener ports; it is not an OS field.",
    ];

    private readonly ProcessIdentityResolver _identities;

    private readonly ConcurrentDictionary<string, DateTimeOffset> _firstSeen = new(StringComparer.Ordinal);

    public IpHelperConnectionSource()
        : this(new ProcessIdentityResolver())
    {
    }

    public IpHelperConnectionSource(ProcessIdentityResolver identityResolver)
    {
        _identities = identityResolver ?? throw new ArgumentNullException(nameof(identityResolver));
    }

    public string Name => "IP Helper (TCP/UDP v4+v6)";

    public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

    public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
        Task.Run(() => Capture(cancellationToken), cancellationToken);

    private ConnectionSnapshot Capture(CancellationToken cancellationToken)
    {
        var capturedUtc = DateTimeOffset.UtcNow;
        var problems = new List<string>();

        var tcp = new List<TcpObservation>(512);
        tcp.AddRange(TryQuery(ReadTcpV4, "IPv4 TCP table", problems));
        tcp.AddRange(TryQuery(ReadTcpV6, "IPv6 TCP table", problems));

        var udp = new List<UdpObservation>(128);
        udp.AddRange(TryQuery(ReadUdpV4, "IPv4 UDP table", problems));
        udp.AddRange(TryQuery(ReadUdpV6, "IPv6 UDP table", problems));

        cancellationToken.ThrowIfCancellationRequested();

        var listeningPorts = new HashSet<(int ProcessId, ushort Port)>();
        foreach (var row in tcp)
        {
            if (EndpointFormatter.IsListening(row.State))
            {
                listeningPorts.Add((row.ProcessId, row.LocalPort));
            }
        }

        var connections = new List<LiveConnection>(tcp.Count + udp.Count);
        var unresolvedPaths = 0;

        foreach (var row in tcp)
        {
            var connection = MapTcp(row, listeningPorts, capturedUtc);
            if (connection.AppPath.Length == 0)
            {
                unresolvedPaths++;
            }

            connections.Add(connection);
        }

        foreach (var row in udp)
        {
            var connection = MapUdp(row, capturedUtc);
            if (connection.AppPath.Length == 0)
            {
                unresolvedPaths++;
            }

            connections.Add(connection);
        }

        PruneFirstSeen(capturedUtc, connections);

        var limitations = new List<string>(StaticLimitations.Length + problems.Count + 1);
        limitations.AddRange(StaticLimitations);

        if (unresolvedPaths > 0)
        {
            limitations.Add($"{unresolvedPaths} socket(s) belong to processes whose executable path is not readable without elevation.");
        }

        limitations.AddRange(problems);

        return new ConnectionSnapshot
        {
            CapturedUtc = capturedUtc,
            Connections = connections,
            ProcessCount = connections.Select(connection => connection.ProcessId).Distinct().Count(),
            SourceName = Name,
            Limitations = limitations,
        };
    }

    private LiveConnection MapTcp(
        TcpObservation row,
        HashSet<(int ProcessId, ushort Port)> listeningPorts,
        DateTimeOffset capturedUtc)
    {
        var identity = _identities.Resolve(row.ProcessId);
        var local = EndpointFormatter.FormatEndpoint(row.LocalAddress, row.LocalPort);
        var remote = EndpointFormatter.FormatRemote(row.RemoteAddress, row.RemotePort);
        var isListening = EndpointFormatter.IsListening(row.State);

        // The owner table has no direction flag. A matching local listener in the non-ephemeral
        // range strongly suggests an accepted (inbound) connection; everything else is outbound.
        var isInbound = isListening ||
                        (listeningPorts.Contains((row.ProcessId, row.LocalPort)) && row.LocalPort < 49152);

        var quality = identity.IsResolved && row.ProcessId > 4
            ? DataQuality.Observed
            : DataQuality.Partial;

        return Create(
            identity,
            row.ProcessId,
            TransportProtocol.Tcp,
            local,
            remote,
            EndpointFormatter.StateName(row.State),
            isListening ? ConnectionDirection.Inbound : isInbound ? ConnectionDirection.Inbound : ConnectionDirection.Outbound,
            row.LocalAddress,
            row.RemoteAddress,
            quality,
            capturedUtc);
    }

    private LiveConnection MapUdp(UdpObservation row, DateTimeOffset capturedUtc)
    {
        var identity = _identities.Resolve(row.ProcessId);

        return Create(
            identity,
            row.ProcessId,
            TransportProtocol.Udp,
            EndpointFormatter.FormatEndpoint(row.LocalAddress, row.LocalPort),
            "—",
            "—",
            ConnectionDirection.Unknown,
            row.LocalAddress,
            remoteAddress: null,
            DataQuality.Partial,
            capturedUtc);
    }

    private LiveConnection Create(
        ProcessIdentityInfo identity,
        int processId,
        TransportProtocol protocol,
        string localEndpoint,
        string remoteEndpoint,
        string state,
        ConnectionDirection direction,
        IPAddress localAddress,
        IPAddress? remoteAddress,
        DataQuality quality,
        DateTimeOffset capturedUtc)
    {
        var key = $"{protocol}|{localEndpoint}|{remoteEndpoint}|{processId}";
        var firstSeen = _firstSeen.GetOrAdd(key, capturedUtc);
        var isLoopback = EndpointFormatter.IsLoopback(localAddress) ||
                         (remoteAddress is not null && EndpointFormatter.IsLoopback(remoteAddress));

        return new LiveConnection
        {
            AppDisplayName = identity.DisplayName,
            AppPath = identity.ExecutablePath,
            ProcessId = processId,
            Protocol = protocol,
            LocalEndpoint = localEndpoint,
            RemoteEndpoint = remoteEndpoint,
            State = state,
            Direction = direction,
            InterfaceName = string.Empty,
            FirstObservedUtc = firstSeen,
            EstimatedUploadBytesPerSecond = null,
            EstimatedDownloadBytesPerSecond = null,
            IsLoopback = isLoopback,
            IsNew = capturedUtc - firstSeen < NewConnectionWindow,
            RuleStatus = ConnectionRuleStatus.Unknown,
            Quality = quality,
        };
    }

    private void PruneFirstSeen(DateTimeOffset capturedUtc, List<LiveConnection> current)
    {
        if (_firstSeen.Count <= current.Count * 2 + 256)
        {
            return;
        }

        var live = current
            .Select(connection => $"{connection.Protocol}|{connection.LocalEndpoint}|{connection.RemoteEndpoint}|{connection.ProcessId}")
            .ToHashSet(StringComparer.Ordinal);

        foreach (var pair in _firstSeen)
        {
            if (!live.Contains(pair.Key) && capturedUtc - pair.Value > FirstSeenRetention)
            {
                _firstSeen.TryRemove(pair.Key, out _);
            }
        }
    }

    private static IEnumerable<TcpObservation> ReadTcpV4()
    {
        foreach (var row in NativeMethods.QueryTcpV4())
        {
            yield return new TcpObservation(
                EndpointFormatter.Ipv4Address(row.LocalAddress),
                EndpointFormatter.HostPort(row.LocalPort),
                EndpointFormatter.Ipv4Address(row.RemoteAddress),
                EndpointFormatter.HostPort(row.RemotePort),
                row.State,
                (int)row.OwningPid);
        }
    }

    private static IEnumerable<TcpObservation> ReadTcpV6()
    {
        foreach (var row in NativeMethods.QueryTcpV6())
        {
            yield return new TcpObservation(
                EndpointFormatter.Ipv6Address(row.LocalAddress, row.LocalScopeId),
                EndpointFormatter.HostPort(row.LocalPort),
                EndpointFormatter.Ipv6Address(row.RemoteAddress, row.RemoteScopeId),
                EndpointFormatter.HostPort(row.RemotePort),
                row.State,
                (int)row.OwningPid);
        }
    }

    private static IEnumerable<UdpObservation> ReadUdpV4()
    {
        foreach (var row in NativeMethods.QueryUdpV4())
        {
            yield return new UdpObservation(
                EndpointFormatter.Ipv4Address(row.LocalAddress),
                EndpointFormatter.HostPort(row.LocalPort),
                (int)row.OwningPid);
        }
    }

    private static IEnumerable<UdpObservation> ReadUdpV6()
    {
        foreach (var row in NativeMethods.QueryUdpV6())
        {
            yield return new UdpObservation(
                EndpointFormatter.Ipv6Address(row.LocalAddress, row.LocalScopeId),
                EndpointFormatter.HostPort(row.LocalPort),
                (int)row.OwningPid);
        }
    }

    private static List<T> TryQuery<T>(Func<IEnumerable<T>> query, string label, List<string> problems)
    {
        try
        {
            return query().ToList();
        }
        catch (Win32Exception exception)
        {
            problems.Add($"{label} unavailable: {exception.Message} (error {exception.NativeErrorCode}).");
            return [];
        }
        catch (InvalidOperationException exception)
        {
            problems.Add($"{label} unavailable: {exception.Message}.");
            return [];
        }
    }

    private readonly record struct TcpObservation(
        IPAddress LocalAddress,
        ushort LocalPort,
        IPAddress RemoteAddress,
        ushort RemotePort,
        uint State,
        int ProcessId);

    private readonly record struct UdpObservation(
        IPAddress LocalAddress,
        ushort LocalPort,
        int ProcessId);
}
