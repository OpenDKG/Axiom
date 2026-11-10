// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Infrastructure.MacOS.ProcessIdentity;

namespace Axiom.Infrastructure.MacOS.Monitoring;

/// <summary>
/// macOS connection inventory. While the AxiomFilter extension streams flow events, connections
/// come from <see cref="FlowTable"/> (every flow with app path, host name, verdict and byte
/// counters). Without the extension the source falls back to libproc socket enumeration, which
/// sees open sockets but no byte counters.
/// </summary>
public sealed class MacConnectionSource : IConnectionSnapshotSource
{
    public const string FlowSourceName = "AxiomFilter flow events";

    public const string LibProcSourceName = "libproc socket table";

    /// <summary>Flow events count as live for this long after the last event.</summary>
    public static readonly TimeSpan StreamingWindow = TimeSpan.FromSeconds(30);

    private static readonly TimeSpan NewConnectionWindow = TimeSpan.FromSeconds(60);

    private static readonly TimeSpan FirstSeenRetention = TimeSpan.FromMinutes(5);

    private static readonly string[] FlowLimitations =
    [
        "Flows and byte counters come from the AxiomFilter network extension; flows that ended while it was not running are not reconstructed.",
        "Byte counters are cumulative per flow as reported by the extension; per-app totals are the sum of observed flow deltas.",
        "Only TCP and UDP flows are listed; other protocols are filtered but not shown.",
    ];

    private static readonly string[] LibProcLimitations =
    [
        "The AxiomFilter network extension is not streaming flow events; connections come from the libproc socket table.",
        "libproc has no per-socket byte counters, so traffic totals and rates are unavailable in this mode.",
        "Connections shorter than the poll interval can be missed; they are not reconstructed.",
        "UDP sockets have no connected peer in most cases, so UDP peer and direction stay unknown.",
    ];

    private readonly FlowTable _flows;

    private readonly FilterStatus _status;

    private readonly IProcessIdentitySource _identities;

    private readonly Func<IReadOnlyList<LibProcSocket>>? _enumerateSockets;

    private readonly TimeProvider _time;

    private readonly ConcurrentDictionary<string, DateTimeOffset> _firstSeen = new(StringComparer.Ordinal);

    public MacConnectionSource(
        FlowTable flows,
        FilterStatus status,
        IProcessIdentitySource identities,
        Func<IReadOnlyList<LibProcSocket>>? enumerateSockets,
        TimeProvider time)
    {
        _flows = flows ?? throw new ArgumentNullException(nameof(flows));
        _status = status ?? throw new ArgumentNullException(nameof(status));
        _identities = identities ?? throw new ArgumentNullException(nameof(identities));
        _enumerateSockets = enumerateSockets;
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    /// <summary>Production wiring: libproc fallback and full identity on macOS, flows only elsewhere.</summary>
    public static MacConnectionSource Create(FlowTable flows, FilterStatus status) =>
        OperatingSystem.IsMacOS()
            ? new MacConnectionSource(flows, status, new MacProcessIdentityResolver(), EnumerateLibProcSockets, TimeProvider.System)
            : new MacConnectionSource(flows, status, PathOnlyIdentitySource.Instance, null, TimeProvider.System);

    public string Name => $"{FlowSourceName} (fallback: {LibProcSourceName})";

    public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

    public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
        Task.Run(() => Capture(cancellationToken), cancellationToken);

    public ConnectionSnapshot Capture(CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        _flows.Prune(now);

        if (_status.IsStreaming(now, StreamingWindow) || _enumerateSockets is null)
        {
            return CaptureFlows(now, cancellationToken);
        }

        return CaptureSockets(now, cancellationToken);
    }

    private ConnectionSnapshot CaptureFlows(DateTimeOffset now, CancellationToken cancellationToken)
    {
        var observations = _flows.Capture(now);
        var connections = new List<LiveConnection>(observations.Count);
        var limitations = new List<string>(FlowLimitations);
        if (!_status.IsStreaming(now, StreamingWindow))
        {
            limitations.Insert(0, "The AxiomFilter network extension is not connected and no libproc fallback is available on this OS.");
        }

        var skipped = 0;
        foreach (var flow in observations)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TransportProtocol protocol;
            if (string.Equals(flow.Protocol, "tcp", StringComparison.Ordinal))
            {
                protocol = TransportProtocol.Tcp;
            }
            else if (string.Equals(flow.Protocol, "udp", StringComparison.Ordinal))
            {
                protocol = TransportProtocol.Udp;
            }
            else
            {
                skipped++;
                continue;
            }

            var identity = _identities.Resolve(flow.ProcessId, flow.Path);
            var remote = ParseAddress(flow.RemoteAddress);
            var blocked = string.Equals(flow.Verdict, "block", StringComparison.Ordinal);

            connections.Add(new LiveConnection
            {
                AppDisplayName = DisplayName(identity, flow.ProcessId),
                AppPath = flow.Path.Length > 0 ? flow.Path : identity.Path,
                ProcessId = flow.ProcessId,
                Protocol = protocol,
                LocalEndpoint = FormatEndpoint(flow.LocalAddress, flow.LocalPort),
                RemoteEndpoint = FormatEndpoint(flow.RemoteAddress, flow.RemotePort),
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
                EstimatedUploadBytesPerSecond = flow.UploadBytesPerSecond,
                EstimatedDownloadBytesPerSecond = flow.DownloadBytesPerSecond,
                ObservedBytesSent = flow.BytesOut,
                ObservedBytesReceived = flow.BytesIn,
                IsLoopback = remote is not null && IPAddress.IsLoopback(remote),
                IsNew = now - flow.OpenedUtc <= NewConnectionWindow,
                RuleStatus = blocked
                    ? flow.RuleId is null ? ConnectionRuleStatus.BlockedByExternalPolicy : ConnectionRuleStatus.BlockedByOwnedRule
                    : ConnectionRuleStatus.Unknown,
                Quality = DataQuality.Observed,
                ParentProcessId = identity.ParentProcessId,
                ParentProcessName = identity.ParentProcessName,
                ParentChain = identity.ParentChain,
                SignerName = identity.SignerName,
                SignatureStatus = identity.SignatureStatus,
                ProductName = identity.BundleId.Length > 0 ? $"{identity.DisplayName} ({identity.BundleId})" : string.Empty,
                FileVersion = identity.Version,
            });
        }

        if (skipped > 0)
        {
            limitations.Add(string.Create(CultureInfo.InvariantCulture, $"{skipped} non-TCP/UDP flow(s) omitted."));
        }

        return new ConnectionSnapshot
        {
            CapturedUtc = now,
            Connections = connections,
            ProcessCount = connections.Select(connection => connection.ProcessId).Distinct().Count(),
            SourceName = FlowSourceName,
            Limitations = limitations,
        };
    }

    private ConnectionSnapshot CaptureSockets(DateTimeOffset now, CancellationToken cancellationToken)
    {
        var sockets = _enumerateSockets!();
        var listeningPorts = sockets
            .Where(socket => socket.Tcp && socket.TcpState == LibProcLayout.TcpStateListen)
            .Select(socket => socket.LocalPort)
            .ToHashSet();

        var connections = new List<LiveConnection>(sockets.Count);
        var live = new HashSet<string>(StringComparer.Ordinal);
        foreach (var socket in sockets)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var local = FormatEndpoint(socket.LocalAddress, socket.LocalPort);
            var remote = IsAny(socket.RemoteAddress) && socket.RemotePort == 0
                ? "—"
                : FormatEndpoint(socket.RemoteAddress, socket.RemotePort);
            var key = string.Create(
                CultureInfo.InvariantCulture,
                $"{(socket.Tcp ? "tcp" : "udp")}|{local}|{remote}|{socket.ProcessId}");
            if (!live.Add(key))
            {
                // libproc reports a socket once per file descriptor: a pid that holds the same
                // socket in several descriptors (dup/fork-inherited) would otherwise list it twice.
                continue;
            }

            var first = _firstSeen.GetOrAdd(key, now);

            var listening = socket.Tcp && socket.TcpState == LibProcLayout.TcpStateListen;
            var direction = !socket.Tcp
                ? ConnectionDirection.Unknown
                : listening || listeningPorts.Contains(socket.LocalPort)
                    ? ConnectionDirection.Inbound
                    : ConnectionDirection.Outbound;

            var identity = _identities.Resolve(socket.ProcessId, null);
            connections.Add(new LiveConnection
            {
                AppDisplayName = DisplayName(identity, socket.ProcessId),
                AppPath = identity.Path,
                ProcessId = socket.ProcessId,
                Protocol = socket.Tcp ? TransportProtocol.Tcp : TransportProtocol.Udp,
                LocalEndpoint = local,
                RemoteEndpoint = remote,
                State = socket.Tcp ? LibProcLayout.TcpStateName(socket.TcpState) : "Bound",
                Direction = direction,
                InterfaceName = string.Empty,
                FirstObservedUtc = first,
                IsLoopback = IPAddress.IsLoopback(socket.RemoteAddress) ||
                             (IsAny(socket.RemoteAddress) && IPAddress.IsLoopback(socket.LocalAddress)),
                IsNew = now - first <= NewConnectionWindow,
                Quality = DataQuality.Partial,
                ParentProcessId = identity.ParentProcessId,
                ParentProcessName = identity.ParentProcessName,
                ParentChain = identity.ParentChain,
                SignerName = identity.SignerName,
                SignatureStatus = identity.SignatureStatus,
                ProductName = identity.BundleId.Length > 0 ? $"{identity.DisplayName} ({identity.BundleId})" : string.Empty,
                FileVersion = identity.Version,
            });
        }

        foreach (var pair in _firstSeen)
        {
            if (!live.Contains(pair.Key) && now - pair.Value > FirstSeenRetention)
            {
                _firstSeen.TryRemove(pair.Key, out _);
            }
        }

        return new ConnectionSnapshot
        {
            CapturedUtc = now,
            Connections = connections,
            ProcessCount = connections.Select(connection => connection.ProcessId).Distinct().Count(),
            SourceName = LibProcSourceName,
            Limitations = LibProcLimitations,
        };
    }

    private static List<LibProcSocket> EnumerateLibProcSockets()
    {
        if (!OperatingSystem.IsMacOS())
        {
            return [];
        }

        var result = new List<LibProcSocket>();
        foreach (var pid in LibProc.ListPids())
        {
            result.AddRange(LibProc.Sockets(pid));
        }

        return result;
    }

    private static string DisplayName(MacProcessIdentity identity, int processId) =>
        identity.DisplayName.Length > 0
            ? identity.DisplayName
            : "pid " + processId.ToString(CultureInfo.InvariantCulture);

    private static IPAddress? ParseAddress(string text) =>
        IPAddress.TryParse(text, out var address) ? address : null;

    private static bool IsAny(IPAddress address) =>
        address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);

    public static string FormatEndpoint(IPAddress address, int port)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return address.AddressFamily == AddressFamily.InterNetworkV6
            ? string.Create(CultureInfo.InvariantCulture, $"[{address}]:{port}")
            : string.Create(CultureInfo.InvariantCulture, $"{address}:{port}");
    }

    public static string FormatEndpoint(string address, int port)
    {
        if (IPAddress.TryParse(address, out var parsed))
        {
            return FormatEndpoint(parsed, port);
        }

        return string.IsNullOrEmpty(address)
            ? "—"
            : string.Create(CultureInfo.InvariantCulture, $"{address}:{port}");
    }
}
