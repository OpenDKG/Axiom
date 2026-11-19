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

    private readonly FlowTable? _flows;

    private readonly Func<IReadOnlyList<string>>? _extraLimitations;

    private readonly ConcurrentDictionary<string, DateTimeOffset> _firstSeen = new(StringComparer.Ordinal);

    public LinuxConnectionSource(
        Func<IReadOnlyList<ProcSocket>> enumerateSockets,
        ILinuxProcessIdentitySource identities,
        TimeProvider time,
        bool privileged,
        FlowTable? flows = null,
        Func<IReadOnlyList<string>>? extraLimitations = null)
    {
        _enumerateSockets = enumerateSockets ?? throw new ArgumentNullException(nameof(enumerateSockets));
        _identities = identities ?? throw new ArgumentNullException(nameof(identities));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _privileged = privileged;
        _flows = flows;
        _extraLimitations = extraLimitations;
    }

    /// <summary>
    /// Production wiring: /proc socket tables for live sockets plus, when the nftables engine is
    /// wired, the blocked attempts it traced (<paramref name="flows"/>, verdict <c>block</c>) — a
    /// rejected SYN never shows up in /proc, so the Connections page would otherwise not see blocks.
    /// </summary>
    public static LinuxConnectionSource Create(FlowTable? flows = null, Func<IReadOnlyList<string>>? extraLimitations = null) => new(
        ProcSocketScanner.Shared.Current,
        new ProcProcessIdentityResolver(),
        TimeProvider.System,
        Environment.IsPrivilegedProcess,
        flows,
        extraLimitations);

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
        if (_extraLimitations is not null)
        {
            limitations.AddRange(_extraLimitations());
        }

        if (!_privileged)
        {
            limitations.Insert(0, UnprivilegedLimitation);
        }

        if (_flows is not null)
        {
            _flows.Prune(now);
            connections.AddRange(BlockedFlows(_flows.Capture(now), now, cancellationToken));
            limitations.Add("Blocked attempts come from the nftables trace of Axiom's block rules (TCP reset / UDP drop); allowed flows are not traced.");
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

    /// <summary>Blocked flows traced by the engine, in the shape MacConnectionSource gives AxiomFilter blocks.</summary>
    private IEnumerable<LiveConnection> BlockedFlows(IReadOnlyList<FlowObservation> observations, DateTimeOffset now, CancellationToken cancellationToken)
    {
        foreach (var flow in observations)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!string.Equals(flow.Verdict, "block", StringComparison.Ordinal))
            {
                continue;
            }

            var protocol = flow.Protocol switch
            {
                "tcp" => TransportProtocol.Tcp,
                "udp" => TransportProtocol.Udp,
                _ => (TransportProtocol?)null,
            };
            if (protocol is null)
            {
                continue;
            }

            var identity = flow.ProcessId > 0
                ? _identities.Resolve(flow.ProcessId, flow.Path)
                : new LinuxProcessIdentity { ProcessId = 0, Path = flow.Path, DisplayName = Path.GetFileName(flow.Path), Uid = 0 };
            var remote = IPAddress.TryParse(flow.RemoteAddress, out var parsed) ? parsed : null;
            yield return new LiveConnection
            {
                AppDisplayName = identity.DisplayName.Length > 0 ? identity.DisplayName : Path.GetFileName(flow.Path),
                AppPath = flow.Path.Length > 0 ? flow.Path : identity.Path,
                ProcessId = Math.Max(0, flow.ProcessId),
                Protocol = protocol.Value,
                LocalEndpoint = EndpointText.Format(flow.LocalAddress, flow.LocalPort),
                RemoteEndpoint = EndpointText.Format(flow.RemoteAddress, flow.RemotePort),
                RemoteHost = flow.RemoteHost,
                State = flow.State,
                Direction = flow.Direction switch
                {
                    "inbound" => ConnectionDirection.Inbound,
                    "outbound" => ConnectionDirection.Outbound,
                    _ => ConnectionDirection.Unknown,
                },
                InterfaceName = string.Empty,
                FirstObservedUtc = flow.OpenedUtc,
                IsLoopback = remote is not null && IPAddress.IsLoopback(remote),
                IsNew = now - flow.OpenedUtc <= NewConnectionWindow,
                RuleStatus = flow.RuleId is null ? ConnectionRuleStatus.BlockedByExternalPolicy : ConnectionRuleStatus.BlockedByOwnedRule,
                Quality = DataQuality.Observed,
                ParentProcessId = identity.ParentProcessId,
                ParentProcessName = identity.ParentProcessName,
                ParentChain = identity.ParentChain,
                CommandLine = identity.CommandLine,
            };
        }
    }
}
