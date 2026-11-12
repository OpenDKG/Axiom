// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.Linux.ProcessIdentity;
using Axiom.Infrastructure.Unix.Monitoring;

namespace Axiom.Infrastructure.Linux.Monitoring;

/// <summary>
/// Linux connection inventory from the kernel socket tables (<see cref="ProcSocketScanner"/>):
/// open TCP/UDP sockets with their owning process, no byte counters. Once the nftables engine
/// streams flow events the daemon switches to <c>FlowTable</c> the way macOS does with AxiomFilter.
/// </summary>
public sealed class LinuxConnectionSource : IConnectionSnapshotSource
{
    public const string SourceName = "/proc socket tables";

    private static readonly TimeSpan NewConnectionWindow = TimeSpan.FromSeconds(60);

    private static readonly TimeSpan FirstSeenRetention = TimeSpan.FromMinutes(5);

    private static readonly string[] BaseLimitations =
    [
        "Connections come from /proc/net/{tcp,tcp6,udp,udp6}; the kernel tables have no per-socket byte counters, so traffic totals and rates are unavailable.",
        "Connections shorter than the poll interval can be missed; they are not reconstructed.",
        "UDP sockets have no connected peer in most cases, so UDP peer and direction stay unknown.",
    ];

    private const string UnprivilegedLimitation =
        "The daemon is not root: only its own user's processes can be attributed; other sockets show pid 0.";

    private readonly Func<IReadOnlyList<ProcSocket>> _enumerateSockets;

    private readonly ILinuxProcessIdentitySource _identities;

    private readonly TimeProvider _time;

    private readonly bool _privileged;

    private readonly ConcurrentDictionary<string, DateTimeOffset> _firstSeen = new(StringComparer.Ordinal);

    public LinuxConnectionSource(
        Func<IReadOnlyList<ProcSocket>> enumerateSockets,
        ILinuxProcessIdentitySource identities,
        TimeProvider time,
        bool privileged)
    {
        _enumerateSockets = enumerateSockets ?? throw new ArgumentNullException(nameof(enumerateSockets));
        _identities = identities ?? throw new ArgumentNullException(nameof(identities));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _privileged = privileged;
    }

    public static LinuxConnectionSource Create() => new(
        ProcSocketScanner.Shared.Current,
        new ProcProcessIdentityResolver(),
        TimeProvider.System,
        Environment.IsPrivilegedProcess);

    public string Name => SourceName;

    public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

    public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
        Task.Run(() => Capture(cancellationToken), cancellationToken);

    public ConnectionSnapshot Capture(CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        var sockets = _enumerateSockets();
        var listeningPorts = sockets
            .Where(socket => socket.Tcp && socket.TcpState == ProcNetTable.TcpStateListen)
            .Select(socket => socket.LocalPort)
            .ToHashSet();

        var connections = new List<LiveConnection>(sockets.Count);
        var live = new HashSet<string>(StringComparer.Ordinal);
        foreach (var socket in sockets)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var local = EndpointText.Format(socket.LocalAddress, socket.LocalPort);
            var remote = EndpointText.IsAny(socket.RemoteAddress) && socket.RemotePort == 0
                ? EndpointText.None
                : EndpointText.Format(socket.RemoteAddress, socket.RemotePort);
            var key = string.Create(
                CultureInfo.InvariantCulture,
                $"{(socket.Tcp ? "tcp" : "udp")}|{local}|{remote}|{socket.ProcessId}|{socket.Inode}");
            if (!live.Add(key))
            {
                continue;
            }

            var first = _firstSeen.GetOrAdd(key, now);
            var listening = socket.Tcp && socket.TcpState == ProcNetTable.TcpStateListen;
            var direction = !socket.Tcp
                ? ConnectionDirection.Unknown
                : listening || listeningPorts.Contains(socket.LocalPort)
                    ? ConnectionDirection.Inbound
                    : ConnectionDirection.Outbound;

            var identity = socket.ProcessId > 0
                ? _identities.Resolve(socket.ProcessId, null)
                : new LinuxProcessIdentity { ProcessId = 0, Path = string.Empty, DisplayName = string.Empty, Uid = socket.Uid };

            connections.Add(new LiveConnection
            {
                AppDisplayName = identity.DisplayName.Length > 0
                    ? identity.DisplayName
                    : socket.ProcessId > 0
                        ? "pid " + socket.ProcessId.ToString(CultureInfo.InvariantCulture)
                        : "uid " + socket.Uid.ToString(CultureInfo.InvariantCulture),
                AppPath = identity.Path,
                ProcessId = socket.ProcessId,
                Protocol = socket.Tcp ? TransportProtocol.Tcp : TransportProtocol.Udp,
                LocalEndpoint = local,
                RemoteEndpoint = remote,
                State = socket.Tcp ? ProcNetTable.TcpStateName(socket.TcpState) : "Bound",
                Direction = direction,
                InterfaceName = string.Empty,
                FirstObservedUtc = first,
                IsLoopback = IPAddress.IsLoopback(socket.RemoteAddress) ||
                             (EndpointText.IsAny(socket.RemoteAddress) && IPAddress.IsLoopback(socket.LocalAddress)),
                IsNew = now - first <= NewConnectionWindow,
                Quality = DataQuality.Partial,
                ParentProcessId = identity.ParentProcessId,
                ParentProcessName = identity.ParentProcessName,
                ParentChain = identity.ParentChain,
                CommandLine = identity.CommandLine,
            });
        }

        foreach (var pair in _firstSeen)
        {
            if (!live.Contains(pair.Key) && now - pair.Value > FirstSeenRetention)
            {
                _firstSeen.TryRemove(pair.Key, out _);
            }
        }

        var limitations = new List<string>(BaseLimitations);
        if (!_privileged)
        {
            limitations.Insert(0, UnprivilegedLimitation);
        }

        return new ConnectionSnapshot
        {
            CapturedUtc = now,
            Connections = connections,
            ProcessCount = connections.Where(connection => connection.ProcessId > 0).Select(connection => connection.ProcessId).Distinct().Count(),
            SourceName = SourceName,
            Limitations = limitations,
        };
    }
}
