// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;

namespace Axiom.Infrastructure.MacOS.Filter;

/// <summary>
/// The latest <c>filter.rules</c> event (docs/MACOS_ARCHITECTURE.md section 3.2): the table the
/// extension enforces, the rules it skipped, and whether the rules file itself was rejected.
/// </summary>
public sealed record FilterRulesReport
{
    /// <summary>Generation of the table in force (-1 before the filter loaded any table).</summary>
    public long Generation { get; init; } = -1;

    /// <summary>Enabled rules the filter enforces.</summary>
    public int Applied { get; init; }

    public IReadOnlyList<FilterRejectedRule> Rejected { get; init; } = [];

    /// <summary>Why the rules file was rejected as a whole; null when the last reload loaded it.</summary>
    public string? Error { get; init; }

    /// <summary>Events the filter dropped so far (monotonic per extension process).</summary>
    public long Dropped { get; init; }

    public DateTimeOffset ReceivedUtc { get; init; }
}

/// <summary>
/// Point-in-time answer to "is generation <see cref="PublishedGeneration"/> enforced right now?"
/// (review 2026-11-12 P0 #2/#3, High #4). <see cref="State"/> is
/// <see cref="FilterEnforcementState.Verified"/> only while the extension is connected and has
/// acknowledged exactly that generation on the current connection with a <c>filter.rules</c>
/// event that carried no file error; the other fields are the evidence behind it.
/// </summary>
public sealed record FilterEnforcementSnapshot(
    FilterEnforcementState State,
    bool Connected,
    long PublishedGeneration,
    long? AckedGeneration,
    DateTimeOffset? LastSeenUtc,
    DateTimeOffset? LastAckUtc,
    FilterRulesReport? Rules)
{
    public bool IsVerified => State == FilterEnforcementState.Verified;

    /// <summary>The filter's own rejection of one rule in the acknowledged table, if any.</summary>
    public string? RejectionReason(string ruleId) =>
        Rules?.Rejected.FirstOrDefault(rejected => string.Equals(rejected.Id, ruleId, StringComparison.OrdinalIgnoreCase))?.Reason;

    /// <summary>A file-level rejection reported after <paramref name="publishedUtc"/> (so it concerns the published table).</summary>
    public string? FileRejectionSince(DateTimeOffset publishedUtc) =>
        Rules is { Error: { Length: > 0 } error } report && report.ReceivedUtc >= publishedUtc ? error : null;
}

/// <summary>
/// Liveness and enforcement state of the AxiomFilter system extension as seen on the flow-event
/// socket. Four things are kept apart on purpose (High #4): when the extension was last seen
/// (<see cref="LastSeenUtc"/>, diagnostic only), whether it is connected now
/// (<see cref="IsConnected"/>, live connection count), which rules generation it last acknowledged
/// (<see cref="AckedGeneration"/>, from <c>filter.rules</c> without an error) and the derived
/// <see cref="Evaluate"/> enforcement state for a published generation. A disconnect degrades
/// enforcement immediately: a hello that was recent a minute ago proves nothing now. After a
/// reconnect the acknowledgement must be fresh (sent on the new connection), which is why the
/// daemon republishes the table on every connect. Thread-safe.
/// </summary>
public sealed class FilterStatus
{
    private readonly object _gate = new();

    private TaskCompletionSource _changed = NewSignal();

    private int _connections;

    /// <summary>Incremented per accepted connection; an ack counts only for the connection it arrived on.</summary>
    private long _connectionEpoch;

    private long _ackEpoch = -1;

    private DateTimeOffset? _lastHelloUtc;

    private DateTimeOffset? _lastEventUtc;

    private DateTimeOffset? _lastSeenUtc;

    private DateTimeOffset? _lastAckUtc;

    private string? _version;

    private long? _generation;

    private long? _ackedGeneration;

    private long _dropped;

    private FilterRulesReport? _rules;

    public bool IsConnected
    {
        get
        {
            lock (_gate)
            {
                return _connections > 0;
            }
        }
    }

    public DateTimeOffset? LastHelloUtc
    {
        get
        {
            lock (_gate)
            {
                return _lastHelloUtc;
            }
        }
    }

    public DateTimeOffset? LastEventUtc
    {
        get
        {
            lock (_gate)
            {
                return _lastEventUtc;
            }
        }
    }

    /// <summary>Last time any byte arrived from the extension (hello, rules or flow event). Diagnostic only.</summary>
    public DateTimeOffset? LastSeenUtc
    {
        get
        {
            lock (_gate)
            {
                return _lastSeenUtc;
            }
        }
    }

    public string? Version
    {
        get
        {
            lock (_gate)
            {
                return _version;
            }
        }
    }

    /// <summary>Rules generation the extension named in its last hello or rules report (diagnostic; not an acknowledgement).</summary>
    public long? LoadedGeneration
    {
        get
        {
            lock (_gate)
            {
                return _generation;
            }
        }
    }

    /// <summary>Generation of the last <c>filter.rules</c> event without a file error, on any connection.</summary>
    public long? AckedGeneration
    {
        get
        {
            lock (_gate)
            {
                return _ackedGeneration;
            }
        }
    }

    public DateTimeOffset? LastAckUtc
    {
        get
        {
            lock (_gate)
            {
                return _lastAckUtc;
            }
        }
    }

    /// <summary>Highest <c>dropped</c> counter seen from the extension (hello or rules event).</summary>
    public long DroppedEvents
    {
        get
        {
            lock (_gate)
            {
                return _dropped;
            }
        }
    }

    /// <summary>The latest <c>filter.rules</c> report, or null until the extension sent one.</summary>
    public FilterRulesReport? Rules
    {
        get
        {
            lock (_gate)
            {
                return _rules;
            }
        }
    }

    public void ClientConnected()
    {
        lock (_gate)
        {
            _connections++;
            _connectionEpoch++;
            Signal();
        }
    }

    public void ClientDisconnected()
    {
        lock (_gate)
        {
            _connections = Math.Max(0, _connections - 1);
            Signal();
        }
    }

    public void Hello(string? version, long? generation, DateTimeOffset now) =>
        Hello(version, generation, null, now);

    public void Hello(string? version, long? generation, long? dropped, DateTimeOffset now)
    {
        lock (_gate)
        {
            _lastHelloUtc = now;
            _lastEventUtc = now;
            _lastSeenUtc = now;
            _version = version;
            _generation = generation;
            if (dropped is { } count)
            {
                _dropped = Math.Max(_dropped, count);
            }
        }
    }

    /// <summary>
    /// Records a <c>filter.rules</c> event; the latest report replaces the previous one. A report
    /// without a file error is the extension's acknowledgement of its generation.
    /// </summary>
    public void RulesReported(FlowEvent rulesEvent, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(rulesEvent);
        if (rulesEvent.Type != FlowEventType.Rules)
        {
            throw new ArgumentException("Expected a filter.rules event.", nameof(rulesEvent));
        }

        lock (_gate)
        {
            _lastEventUtc = now;
            _lastSeenUtc = now;
            if (rulesEvent.Dropped is { } count)
            {
                _dropped = Math.Max(_dropped, count);
            }

            // A rejected file keeps the previous table: its generation is the one still enforced.
            if (rulesEvent.Generation is { } generation)
            {
                _generation = generation;
                if (string.IsNullOrEmpty(rulesEvent.Error))
                {
                    _ackedGeneration = generation;
                    _ackEpoch = _connectionEpoch;
                    _lastAckUtc = now;
                }
            }

            _rules = new FilterRulesReport
            {
                Generation = rulesEvent.Generation ?? -1,
                Applied = rulesEvent.Applied ?? 0,
                Rejected = rulesEvent.Rejected,
                Error = rulesEvent.Error,
                Dropped = _dropped,
                ReceivedUtc = now,
            };
            Signal();
        }
    }

    public void EventSeen(DateTimeOffset now)
    {
        lock (_gate)
        {
            _lastEventUtc = now;
            _lastSeenUtc = now;
        }
    }

    /// <summary>
    /// Enforcement state of <paramref name="publishedGeneration"/> now: never seen →
    /// <see cref="FilterEnforcementState.Unavailable"/>; seen but not connected →
    /// <see cref="FilterEnforcementState.Degraded"/>; connected without a matching acknowledgement
    /// on this connection (older or newer generation, file rejected, nothing yet) →
    /// <see cref="FilterEnforcementState.Pending"/>; otherwise <see cref="FilterEnforcementState.Verified"/>.
    /// </summary>
    public FilterEnforcementState Evaluate(long publishedGeneration)
    {
        lock (_gate)
        {
            return EvaluateLocked(publishedGeneration);
        }
    }

    public FilterEnforcementSnapshot Snapshot(long publishedGeneration)
    {
        lock (_gate)
        {
            return new FilterEnforcementSnapshot(
                EvaluateLocked(publishedGeneration),
                _connections > 0,
                publishedGeneration,
                _ackedGeneration,
                _lastSeenUtc,
                _lastAckUtc,
                _rules);
        }
    }

    /// <summary>
    /// Waits (bounded by <paramref name="timeout"/>) until the extension acknowledges
    /// <paramref name="publishedGeneration"/>, rejects the file published at
    /// <paramref name="publishedUtc"/>, or disconnects. Returns at once when the extension is
    /// not connected; the caller re-reads <see cref="Snapshot"/> afterwards.
    /// </summary>
    public async Task WaitForAcknowledgementAsync(
        long publishedGeneration,
        DateTimeOffset publishedUtc,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = Environment.TickCount64 + (long)Math.Max(0, timeout.TotalMilliseconds);
        while (true)
        {
            Task changed;
            lock (_gate)
            {
                var state = EvaluateLocked(publishedGeneration);
                if (state != FilterEnforcementState.Pending ||
                    (_rules is { Error.Length: > 0 } report && report.ReceivedUtc >= publishedUtc))
                {
                    return;
                }

                changed = _changed.Task;
            }

            var remaining = deadline - Environment.TickCount64;
            if (remaining <= 0)
            {
                return;
            }

            var completed = await Task.WhenAny(changed, Task.Delay(TimeSpan.FromMilliseconds(remaining), cancellationToken)).ConfigureAwait(false);
            if (completed != changed)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return;
            }
        }
    }

    /// <summary>Flow events are the live connection source: connected or an event within <paramref name="window"/>.</summary>
    public bool IsStreaming(DateTimeOffset now, TimeSpan window)
    {
        lock (_gate)
        {
            return _connections > 0 || (_lastEventUtc is { } last && now - last <= window);
        }
    }

    private FilterEnforcementState EvaluateLocked(long publishedGeneration)
    {
        if (_connections == 0)
        {
            return _lastSeenUtc is null ? FilterEnforcementState.Unavailable : FilterEnforcementState.Degraded;
        }

        return _ackEpoch == _connectionEpoch && _ackedGeneration == publishedGeneration
            ? FilterEnforcementState.Verified
            : FilterEnforcementState.Pending;
    }

    private void Signal()
    {
        var previous = _changed;
        _changed = NewSignal();
        previous.TrySetResult();
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}
