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

    /// <summary>
    /// The accepted connection the report arrived on (<see cref="FilterStatus"/> connection id).
    /// A report from a previous connection is history, never an acknowledgement for the current
    /// extension instance.
    /// </summary>
    public long ConnectionId { get; init; } = -1;

    /// <summary>
    /// Ids the filter says it enforces (additive <c>ruleIds</c> field of <c>filter.rules</c>);
    /// null when the extension did not echo them, which means "unknown", not "none".
    /// </summary>
    public IReadOnlyList<string>? AppliedRuleIds { get; init; }

    /// <summary>The report says the rules file was rejected (the generation named is the one still in force).</summary>
    public bool IsError => !string.IsNullOrEmpty(Error);

    public bool Enforces(string ruleId) =>
        AppliedRuleIds?.Any(id => string.Equals(id, ruleId, StringComparison.OrdinalIgnoreCase)) == true;
}

/// <summary>
/// Point-in-time answer to "is generation <see cref="PublishedGeneration"/> enforced right now?"
/// (review 2026-11-12 P0 #2/#3, High #4; review #2 MAC-1). <see cref="State"/> is
/// <see cref="FilterEnforcementState.Verified"/> only while the extension is connected and its
/// <b>latest</b> <c>filter.rules</c> report arrived on the current connection, carried no file
/// error and names exactly that generation; the other fields are the evidence behind it.
/// <see cref="ExpectedRuleIds"/> is the daemon's own record of what it published under that
/// generation (null when the generation was not published by this daemon process), so the
/// per-rule questions <see cref="RuleVerified"/> / <see cref="RuleVerifiedAbsent"/> are answered
/// against the acknowledged effective table, not the global generation alone.
/// </summary>
public sealed record FilterEnforcementSnapshot(
    FilterEnforcementState State,
    bool Connected,
    long PublishedGeneration,
    long? AckedGeneration,
    DateTimeOffset? LastSeenUtc,
    DateTimeOffset? LastAckUtc,
    FilterRulesReport? Rules,
    IReadOnlyList<string>? ExpectedRuleIds = null)
{
    public bool IsVerified => State == FilterEnforcementState.Verified;

    /// <summary>The filter's own rejection of one rule in the acknowledged table, if any.</summary>
    public string? RejectionReason(string ruleId) =>
        Rules?.Rejected.FirstOrDefault(rejected => string.Equals(rejected.Id, ruleId, StringComparison.OrdinalIgnoreCase))?.Reason;

    /// <summary>The daemon published <paramref name="ruleId"/> under <see cref="PublishedGeneration"/>.</summary>
    public bool Expected(string ruleId) =>
        ExpectedRuleIds?.Any(id => string.Equals(id, ruleId, StringComparison.OrdinalIgnoreCase)) == true;

    /// <summary>
    /// The rule is proven in force as published: the generation is verified, the daemon published
    /// the rule in it, the filter did not reject it and, when the filter echoes its effective ids
    /// (<c>ruleIds</c>), lists it — or, for a disabled rule (<paramref name="enabled"/> false,
    /// which the filter skips by contract), does not list it.
    /// </summary>
    public bool RuleVerified(string ruleId, bool enabled = true) =>
        IsVerified &&
        Expected(ruleId) &&
        RejectionReason(ruleId) is null &&
        (Rules?.AppliedRuleIds is null || Rules.Enforces(ruleId) == enabled);

    /// <summary>
    /// The rule is proven gone: the generation is verified, the daemon's published table for it
    /// does not contain the rule and the filter (when it echoes ids) does not enforce it.
    /// </summary>
    public bool RuleVerifiedAbsent(string ruleId) =>
        IsVerified &&
        ExpectedRuleIds is not null &&
        !Expected(ruleId) &&
        !(Rules?.Enforces(ruleId) ?? false);

    /// <summary>A file-level rejection reported after <paramref name="publishedUtc"/> (so it concerns the published table).</summary>
    public string? FileRejectionSince(DateTimeOffset publishedUtc) =>
        Rules is { Error: { Length: > 0 } error } report && report.ReceivedUtc >= publishedUtc ? error : null;
}

/// <summary>
/// Liveness and enforcement state of the AxiomFilter system extension as seen on the flow-event
/// socket. Four things are kept apart on purpose (High #4): when the extension was last seen
/// (<see cref="LastSeenUtc"/>, from the current connection, diagnostic only), whether a current
/// connection is open now (<see cref="IsConnected"/>), which rules generation that connection last
/// acknowledged (<see cref="AckedGeneration"/>, from <c>filter.rules</c> without an error) and the derived
/// <see cref="Evaluate"/> enforcement state for a published generation. A disconnect degrades
/// enforcement immediately: a hello that was recent a minute ago proves nothing now. After a
/// reconnect the acknowledgement must be fresh (sent on the new connection), which is why the
/// daemon republishes the table on every connect. Thread-safe.
/// </summary>
public sealed class FilterStatus
{
    private readonly object _gate = new();

    private TaskCompletionSource _changed = NewSignal();

    /// <summary>Accepted connections that have not disconnected yet (up to four in the server).</summary>
    private readonly HashSet<long> _openConnections = [];

    /// <summary>Incremented per accepted connection; the newest one is the current session.</summary>
    private long _nextConnectionId;

    /// <summary>The only connection allowed to change current enforcement, liveness and diagnostics.</summary>
    private long? _currentConnectionId;

    private DateTimeOffset? _lastHelloUtc;

    private DateTimeOffset? _lastEventUtc;

    private DateTimeOffset? _lastSeenUtc;

    private DateTimeOffset? _lastAckUtc;

    private string? _version;

    private long? _generation;

    private long? _ackedGeneration;

    private long _dropped;

    /// <summary>Latest <c>filter.rules</c> report (ok or error) from the current connection.</summary>
    private FilterRulesReport? _rules;

    /// <summary>What this daemon process last published: generation and the rule ids in that table.</summary>
    private (long Generation, IReadOnlyList<string> RuleIds)? _published;

    public bool IsConnected
    {
        get
        {
            lock (_gate)
            {
                return _currentConnectionId is not null;
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

    /// <summary>Last time the current connection sent a hello, rules report or flow event. Diagnostic only.</summary>
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

    /// <summary>Generation of the last <c>filter.rules</c> event without a file error on the current connection.</summary>
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

    /// <summary>
    /// Registers an accepted connection and makes it the current session. Returns the token every
    /// later event from that connection must carry; only the newest accepted connection can update
    /// the current generation, acknowledgement, rules report, liveness or diagnostics.
    /// </summary>
    public long ClientConnected()
    {
        lock (_gate)
        {
            var connectionId = ++_nextConnectionId;
            _openConnections.Add(connectionId);
            _currentConnectionId = connectionId;
            Signal();
            return connectionId;
        }
    }

    /// <summary>
    /// Removes one connection. Disconnecting the current session revokes its verification even when
    /// an older connection is still open; disconnecting a stale connection changes nothing current.
    /// </summary>
    public void ClientDisconnected(long connectionId)
    {
        lock (_gate)
        {
            if (!_openConnections.Remove(connectionId))
            {
                return;
            }

            if (_currentConnectionId == connectionId)
            {
                _currentConnectionId = null;
            }

            Signal();
        }
    }

    public void Hello(long connectionId, string? version, long? generation, DateTimeOffset now) =>
        Hello(connectionId, version, generation, null, now);

    public void Hello(long connectionId, string? version, long? generation, long? dropped, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (_currentConnectionId != connectionId)
            {
                return;
            }

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
    /// Records what the daemon just wrote to rules.json: the expected-rules snapshot for
    /// <paramref name="generation"/>. Only the latest publish is kept; an acknowledgement is matched
    /// against it rule by rule (<see cref="FilterEnforcementSnapshot.RuleVerified"/>).
    /// </summary>
    public void Published(long generation, IEnumerable<string> ruleIds)
    {
        ArgumentNullException.ThrowIfNull(ruleIds);
        lock (_gate)
        {
            _published = (generation, ruleIds.ToArray());
            Signal();
        }
    }

    /// <summary>
    /// Records a <c>filter.rules</c> event; the latest report replaces the previous one, whatever
    /// its outcome. A report without a file error is the extension's acknowledgement of its
    /// generation; a report <b>with</b> an error revokes any earlier acknowledgement of the same
    /// generation (review #2 MAC-1): the file in force is no longer the one the daemon published.
    /// </summary>
    public void RulesReported(long connectionId, FlowEvent rulesEvent, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(rulesEvent);
        if (rulesEvent.Type != FlowEventType.Rules)
        {
            throw new ArgumentException("Expected a filter.rules event.", nameof(rulesEvent));
        }

        lock (_gate)
        {
            if (_currentConnectionId != connectionId)
            {
                return;
            }

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
                ConnectionId = connectionId,
                AppliedRuleIds = rulesEvent.RuleIds,
            };
            Signal();
        }
    }

    public void EventSeen(long connectionId, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (_currentConnectionId != connectionId)
            {
                return;
            }

            _lastEventUtc = now;
            _lastSeenUtc = now;
        }
    }

    /// <summary>
    /// Enforcement state of <paramref name="publishedGeneration"/> now: never seen →
    /// <see cref="FilterEnforcementState.Unavailable"/>; seen but not connected →
    /// <see cref="FilterEnforcementState.Degraded"/>; connected but the latest report is not a
    /// clean acknowledgement of exactly this generation on this connection (older or newer
    /// generation, file rejected — also when rejected after an earlier ack of the same generation —,
    /// nothing yet, report from the previous connection) →
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
                _currentConnectionId is not null,
                publishedGeneration,
                _ackedGeneration,
                _lastSeenUtc,
                _lastAckUtc,
                _rules,
                _published is { } published && published.Generation == publishedGeneration ? published.RuleIds : null);
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
            return _currentConnectionId is not null || (_lastEventUtc is { } last && now - last <= window);
        }
    }

    private FilterEnforcementState EvaluateLocked(long publishedGeneration)
    {
        // No current session: a stale connection that has not seen EOF yet proves nothing.
        if (_currentConnectionId is not { } currentConnectionId)
        {
            return _lastSeenUtc is null ? FilterEnforcementState.Unavailable : FilterEnforcementState.Degraded;
        }

        // Verified needs the LATEST report, on THIS accepted connection, error-free, for THIS
        // generation. An earlier successful ack with the same number does not count once a later
        // report said the file is rejected (MAC-1), nor does a report from another connection,
        // even when that connection is still open.
        return _rules is { } latest &&
               latest.ConnectionId == currentConnectionId &&
               !latest.IsError &&
               latest.Generation == publishedGeneration
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
