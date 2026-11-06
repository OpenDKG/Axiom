// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Axiom.Contracts.Monitoring;

namespace Axiom.Infrastructure.Linux.ProcFs;

/// <summary>
/// Read-only TCP/UDP inventory from <c>/proc/net</c> with process attribution from
/// <c>/proc/&lt;pid&gt;/fd</c>. Runs without elevation for the caller's own sockets; root sees every
/// process. Unattributable sockets are reported as partial, never guessed.
/// </summary>
public sealed class ProcConnectionSource : IConnectionSnapshotSource
{
    private static readonly TimeSpan NewConnectionWindow = TimeSpan.FromSeconds(60);

    private readonly TimeSpan _firstSeenRetention;

    private static readonly string[] StaticLimitations =
    [
        "Byte counts are not exposed by the /proc socket tables; per-flow throughput is not measured.",
        "Sockets in processes the service may not inspect stay unattributed and are marked partial.",
        "Connections shorter than the poll interval can be missed; they are not reconstructed.",
        "UDP direction is not an OS field; it stays unknown even when a peer address is present.",
        "AF_UNIX and AF_NETLINK sockets are outside this TCP/UDP inventory.",
        "TCP direction is inferred from listening local ports; it is not an OS field.",
    ];

    private readonly string _procRoot;

    private readonly ProcSocketInventory _inventory;

    private readonly ProcProcessIdentityResolver _identities;

    private readonly ConcurrentDictionary<string, FirstSeenEntry> _firstSeen = new(StringComparer.Ordinal);

    private readonly HashSet<string> _liveKeys = new(StringComparer.Ordinal);

    public ProcConnectionSource()
        : this("/proc")
    {
    }

    public ProcConnectionSource(
        string procRoot,
        ProcSocketInventory? inventory = null,
        ProcProcessIdentityResolver? identities = null,
        TimeSpan? firstSeenRetention = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(procRoot);

        _procRoot = procRoot;
        _inventory = inventory ?? new ProcSocketInventory(procRoot);
        _identities = identities ?? new ProcProcessIdentityResolver(procRoot);
        _firstSeenRetention = firstSeenRetention ?? TimeSpan.FromMinutes(5);
    }

    public string Name => "procfs (TCP/UDP v4+v6)";

    public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

    public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
        Task.Run(() => Capture(cancellationToken), cancellationToken);

    private ConnectionSnapshot Capture(CancellationToken cancellationToken)
    {
        var capturedUtc = DateTimeOffset.UtcNow;
        var problems = new List<string>();

        var tcp = new List<ProcSocketRow>(512);
        tcp.AddRange(ReadTable("tcp", ipv6: false, TransportProtocol.Tcp, problems));
        tcp.AddRange(ReadTable("tcp6", ipv6: true, TransportProtocol.Tcp, problems));

        var udp = new List<ProcSocketRow>(128);
        udp.AddRange(ReadTable("udp", ipv6: false, TransportProtocol.Udp, problems));
        udp.AddRange(ReadTable("udp6", ipv6: true, TransportProtocol.Udp, problems));

        cancellationToken.ThrowIfCancellationRequested();

        var ownership = _inventory.BuildInodeOwnerMap(cancellationToken);

        var listenerPorts = new HashSet<(int ProcessId, ushort Port)>();
        foreach (var row in tcp)
        {
            if (ProcNetTable.IsListening(row.State))
            {
                var listenerPid = row.Inode > 0 &&
                                  ownership.Owners.TryGetValue(row.Inode, out var listenerOwner) &&
                                  !ownership.SharedInodes.Contains(row.Inode)
                    ? listenerOwner.ProcessId
                    : 0;
                listenerPorts.Add((listenerPid, row.LocalPort));
            }
        }

        var connections = new List<LiveConnection>(tcp.Count + udp.Count);
        var unresolved = 0;
        var attributed = 0;
        var sharedRows = 0;
        var recycledRows = 0;

        foreach (var row in tcp)
        {
            var connection = Map(row, ownership, listenerPorts, capturedUtc, ref sharedRows, ref recycledRows);
            if (connection.Quality != DataQuality.Observed)
            {
                unresolved++;
            }
            else
            {
                attributed++;
            }

            connections.Add(connection);
        }

        foreach (var row in udp)
        {
            var connection = Map(row, ownership, listenerPorts, capturedUtc, ref sharedRows, ref recycledRows);
            if (connection.Quality != DataQuality.Observed)
            {
                unresolved++;
            }
            else
            {
                attributed++;
            }

            connections.Add(connection);
        }

        PruneFirstSeen(capturedUtc);

        var limitations = new List<string>(StaticLimitations.Length + problems.Count + 3);
        limitations.AddRange(StaticLimitations);
        if (unresolved > 0)
        {
            limitations.Add($"{unresolved} socket(s) could not be attributed to a readable executable.");
        }

        if (sharedRows > 0)
        {
            limitations.Add(
                $"{sharedRows} socket row(s) are shared by several processes or changed owner during " +
                "capture; they are reported unattributed instead of guessing one process.");
        }

        if (recycledRows > 0)
        {
            limitations.Add(
                $"{recycledRows} socket row(s) had a process start time that no longer matched the " +
                "PID during capture; they are reported unattributed.");
        }

        if (connections.Count > 0 && attributed == 0)
        {
            limitations.Add(
                "The service cannot read socket owners from other processes (no ptrace capability in its sandbox). " +
                "Run the system service for full attribution; this capture is partial.");
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

    private IEnumerable<ProcSocketRow> ReadTable(
        string fileName,
        bool ipv6,
        TransportProtocol protocol,
        List<string> problems)
    {
        var path = Path.Combine(_procRoot, "net", fileName);

        try
        {
            return ProcNetTable.Parse(File.ReadAllText(path), ipv6, protocol);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            problems.Add($"/proc/net/{fileName} unavailable: {exception.Message}.");
            return [];
        }
    }

    private LiveConnection Map(
        ProcSocketRow row,
        SocketOwnershipMap ownership,
        HashSet<(int ProcessId, ushort Port)> listenerPorts,
        DateTimeOffset capturedUtc,
        ref int sharedRows,
        ref int recycledRows)
    {
        SocketOwner owner = default;
        var hasOwner = row.Inode > 0 &&
                       ownership.Owners.TryGetValue(row.Inode, out owner);
        var pid = hasOwner ? owner.ProcessId : 0;
        var identity = _identities.Resolve(pid);

        // The PID may be recycled between the fd walk and this lookup. A start-time mismatch is
        // not the socket's owner, so refuse the attribution rather than show an unrelated app.
        // A missing recorded start time is not "no mismatch": it is missing evidence, so the row
        // stays unattributed instead of becoming Observed on executable alone.
        var startTimeMismatch = hasOwner &&
                                (owner.StartTimeTicks == 0 ||
                                 identity.StartTimeTicks != owner.StartTimeTicks);
        var shared = row.Inode > 0 && ownership.SharedInodes.Contains(row.Inode);

        if (shared)
        {
            sharedRows++;
        }

        if (startTimeMismatch)
        {
            recycledRows++;
        }

        var ambiguous = shared || startTimeMismatch;
        if (ambiguous)
        {
            pid = 0;
            identity = _identities.Resolve(0);
        }

        var isListening = row.Protocol == TransportProtocol.Tcp && ProcNetTable.IsListening(row.State);
        var hasPeer = row.RemoteAddress is not null && row.RemotePort != 0;

        // Accepted connections share the listener's local port and (normally) its owner PID. The
        // old ephemeral-port guard mislabelled servers on ports above 49151, so match the exact
        // (pid, port) listener instead.
        var isInbound = isListening ||
                        (hasPeer && listenerPorts.Contains((pid, row.LocalPort)));

        var direction = row.Protocol == TransportProtocol.Udp || (ambiguous && !isListening)
            ? ConnectionDirection.Unknown
            : isInbound
                ? ConnectionDirection.Inbound
                : ConnectionDirection.Outbound;

        var local = FormatEndpoint(row.LocalAddress, row.LocalPort);
        var remote = hasPeer ? FormatEndpoint(row.RemoteAddress!, row.RemotePort) : "—";

        var quality = !identity.IsResolved || pid <= 4 ? DataQuality.Partial : DataQuality.Observed;

        // The socket inode identifies the socket itself: a process that closes and rebinds the
        // same endpoint must not inherit the old first-seen time. The start time is kept in the
        // entry so a recycled PID also starts a new window.
        var key = string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{row.Protocol}|{local}|{remote}|{pid}|{row.Inode}");
        _liveKeys.Add(key);
        var entry = _firstSeen.AddOrUpdate(
            key,
            _ => new FirstSeenEntry(identity.StartTimeTicks, capturedUtc),
            (_, existing) => existing.StartTimeTicks == identity.StartTimeTicks
                ? existing
                : new FirstSeenEntry(identity.StartTimeTicks, capturedUtc));
        var firstSeen = entry.FirstSeenUtc;

        var isLoopback = IPAddress.IsLoopback(row.LocalAddress) ||
                         (row.RemoteAddress is not null && IPAddress.IsLoopback(row.RemoteAddress));

        return new LiveConnection
        {
            AppDisplayName = identity.DisplayName,
            AppPath = identity.ExecutablePath,
            ProcessId = pid,
            Protocol = row.Protocol,
            LocalEndpoint = local,
            RemoteEndpoint = remote,
            State = row.State,
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

    private void PruneFirstSeen(DateTimeOffset capturedUtc)
    {
        // Unconditional expiry of sockets that are no longer in the capture. A size threshold left
        // a closed socket's entry around indefinitely, so a rebound endpoint could report an old
        // first-seen time.
        foreach (var pair in _firstSeen)
        {
            if (!_liveKeys.Contains(pair.Key) && capturedUtc - pair.Value.FirstSeenUtc >= _firstSeenRetention)
            {
                _firstSeen.TryRemove(pair.Key, out _);
            }
        }

        _liveKeys.Clear();
    }

    private readonly record struct FirstSeenEntry(long StartTimeTicks, DateTimeOffset FirstSeenUtc);

    private static string FormatEndpoint(IPAddress address, ushort port) =>
        address.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{address}]:{port}"
            : $"{address}:{port}";
}
