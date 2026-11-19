// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.MacOS.Filter;

namespace Axiom.Infrastructure.MacOS.Monitoring;

/// <summary>One flow as reported by <see cref="FlowTable.Capture"/>.</summary>
public sealed record FlowObservation
{
    public required string Id { get; init; }

    public required int ProcessId { get; init; }

    public required string Path { get; init; }

    public required string Direction { get; init; }

    public required string Protocol { get; init; }

    public required string LocalAddress { get; init; }

    public required int LocalPort { get; init; }

    public required string RemoteAddress { get; init; }

    public required int RemotePort { get; init; }

    public required string RemoteHost { get; init; }

    public required string Verdict { get; init; }

    public string? RuleId { get; init; }

    public required DateTimeOffset OpenedUtc { get; init; }

    public DateTimeOffset? ClosedUtc { get; init; }

    /// <summary>Bytes received by the app (filter <c>bytesIn</c>).</summary>
    public long BytesIn { get; init; }

    /// <summary>Bytes sent by the app (filter <c>bytesOut</c>).</summary>
    public long BytesOut { get; init; }

    public double DownloadBytesPerSecond { get; init; }

    public double UploadBytesPerSecond { get; init; }

    /// <summary><c>Established</c>, <c>Closed</c> or <c>Blocked</c>.</summary>
    public required string State { get; init; }
}

/// <summary>
/// Live flow table fed by AxiomFilter events. Open flows stay until closed; a closed or blocked
/// flow is reported by exactly one more <see cref="Capture"/> so its final byte counts reach the
/// per-app totals, then it is dropped. Rates are per flow, between consecutive captures.
/// Bounded: the oldest flows are evicted beyond <see cref="MaxFlows"/>. Thread-safe.
/// </summary>
public sealed class FlowTable
{
    public const int MaxFlows = 8192;

    /// <summary>Closed flows that were never captured are dropped after this.</summary>
    public static readonly TimeSpan ClosedRetention = TimeSpan.FromSeconds(30);

    private readonly object _gate = new();

    private readonly Dictionary<string, Entry> _flows = new(StringComparer.Ordinal);

    public long OrphanEvents { get; private set; }

    public long EvictedFlows { get; private set; }

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _flows.Count;
            }
        }
    }

    public void Apply(FlowEvent flowEvent, DateTimeOffset receivedUtc)
    {
        ArgumentNullException.ThrowIfNull(flowEvent);

        lock (_gate)
        {
            switch (flowEvent.Type)
            {
                case FlowEventType.Open:
                    var opened = Sane(flowEvent.Timestamp, receivedUtc);
                    if (_flows.TryGetValue(flowEvent.Id, out var existing))
                    {
                        // Duplicate open (filter reconnect replay): refresh facts, keep counters.
                        existing.Facts = flowEvent;
                        break;
                    }

                    _flows[flowEvent.Id] = new Entry(flowEvent, opened);
                    if (string.Equals(flowEvent.Verdict, "block", StringComparison.Ordinal))
                    {
                        _flows[flowEvent.Id].ClosedUtc = opened;
                    }

                    EvictIfNeeded();
                    break;

                case FlowEventType.Stats:
                case FlowEventType.Close:
                    if (!_flows.TryGetValue(flowEvent.Id, out var entry))
                    {
                        OrphanEvents++;
                        break;
                    }

                    // Counters are cumulative per flow; never let a reordered event move them back.
                    if (flowEvent.BytesIn is { } bytesIn)
                    {
                        entry.BytesIn = Math.Max(entry.BytesIn, bytesIn);
                    }

                    if (flowEvent.BytesOut is { } bytesOut)
                    {
                        entry.BytesOut = Math.Max(entry.BytesOut, bytesOut);
                    }

                    if (flowEvent.Type == FlowEventType.Close)
                    {
                        entry.ClosedUtc ??= Sane(flowEvent.Timestamp, receivedUtc);
                    }

                    break;

                case FlowEventType.Hello:
                default:
                    break;
            }
        }
    }

    public IReadOnlyList<FlowObservation> Capture(DateTimeOffset now)
    {
        lock (_gate)
        {
            var result = new List<FlowObservation>(_flows.Count);
            var remove = new List<string>();

            foreach (var (id, entry) in _flows)
            {
                var elapsed = (now - (entry.LastCaptureUtc ?? entry.OpenedUtc)).TotalSeconds;
                var download = elapsed > 0 ? Math.Max(0, entry.BytesIn - entry.CapturedIn) / elapsed : 0;
                var upload = elapsed > 0 ? Math.Max(0, entry.BytesOut - entry.CapturedOut) / elapsed : 0;
                var facts = entry.Facts;
                var blocked = string.Equals(facts.Verdict, "block", StringComparison.Ordinal);

                result.Add(new FlowObservation
                {
                    Id = id,
                    ProcessId = facts.ProcessId,
                    Path = facts.Path,
                    Direction = facts.Direction,
                    Protocol = facts.Protocol,
                    LocalAddress = facts.LocalAddress,
                    LocalPort = facts.LocalPort,
                    RemoteAddress = facts.RemoteAddress,
                    RemotePort = facts.RemotePort,
                    RemoteHost = facts.RemoteHost,
                    Verdict = facts.Verdict,
                    RuleId = facts.RuleId,
                    OpenedUtc = entry.OpenedUtc,
                    ClosedUtc = entry.ClosedUtc,
                    BytesIn = entry.BytesIn,
                    BytesOut = entry.BytesOut,
                    DownloadBytesPerSecond = download,
                    UploadBytesPerSecond = upload,
                    State = blocked ? "Blocked" : entry.ClosedUtc is null ? "Established" : "Closed",
                });

                entry.CapturedIn = entry.BytesIn;
                entry.CapturedOut = entry.BytesOut;
                entry.LastCaptureUtc = now;

                if (entry.ClosedUtc is not null)
                {
                    remove.Add(id);
                }
            }

            foreach (var id in remove)
            {
                _flows.Remove(id);
            }

            return result;
        }
    }

    /// <summary>Drops closed flows nobody captured (no monitoring poll for a while).</summary>
    public void Prune(DateTimeOffset now)
    {
        lock (_gate)
        {
            foreach (var id in _flows
                         .Where(pair => pair.Value.ClosedUtc is { } closed && now - closed > ClosedRetention)
                         .Select(pair => pair.Key)
                         .ToList())
            {
                _flows.Remove(id);
            }
        }
    }

    private void EvictIfNeeded()
    {
        if (_flows.Count <= MaxFlows)
        {
            return;
        }

        foreach (var id in _flows
                     .OrderBy(pair => pair.Value.ClosedUtc is null ? 1 : 0)
                     .ThenBy(pair => pair.Value.OpenedUtc)
                     .Take(_flows.Count - MaxFlows)
                     .Select(pair => pair.Key)
                     .ToList())
        {
            _flows.Remove(id);
            EvictedFlows++;
        }
    }

    private static DateTimeOffset Sane(DateTimeOffset? timestamp, DateTimeOffset receivedUtc) =>
        timestamp is { } value && (value - receivedUtc).Duration() < TimeSpan.FromHours(1) ? value : receivedUtc;

    private sealed class Entry(FlowEvent facts, DateTimeOffset openedUtc)
    {
        public FlowEvent Facts { get; set; } = facts;

        public DateTimeOffset OpenedUtc { get; } = openedUtc;

        public DateTimeOffset? ClosedUtc { get; set; }

        public long BytesIn { get; set; } = facts.BytesIn ?? 0;

        public long BytesOut { get; set; } = facts.BytesOut ?? 0;

        public long CapturedIn { get; set; }

        public long CapturedOut { get; set; }

        public DateTimeOffset? LastCaptureUtc { get; set; }
    }
}
