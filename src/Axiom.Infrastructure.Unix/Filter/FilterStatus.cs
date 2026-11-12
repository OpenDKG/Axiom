// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.Unix.Filter;

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
/// Liveness of the AxiomFilter system extension as seen on the flow-event socket: connection
/// count, the last <c>filter.hello</c> (version and the rules generation it loaded), the last
/// <c>filter.rules</c> report and the last event of any kind. Thread-safe.
/// </summary>
public sealed class FilterStatus
{
    /// <summary>A hello older than this (with no connection) no longer proves the extension is active.</summary>
    public static readonly TimeSpan HelloLifetime = TimeSpan.FromMinutes(10);

    private readonly object _gate = new();

    private int _connections;

    private DateTimeOffset? _lastHelloUtc;

    private DateTimeOffset? _lastEventUtc;

    private string? _version;

    private long? _generation;

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

    /// <summary>Rules generation reported by the extension in its last hello or rules report.</summary>
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
        }
    }

    public void ClientDisconnected()
    {
        lock (_gate)
        {
            _connections = Math.Max(0, _connections - 1);
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
            _version = version;
            _generation = generation;
            if (dropped is { } count)
            {
                _dropped = Math.Max(_dropped, count);
            }
        }
    }

    /// <summary>Records a <c>filter.rules</c> event; the latest report replaces the previous one.</summary>
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
            if (rulesEvent.Dropped is { } count)
            {
                _dropped = Math.Max(_dropped, count);
            }

            // A rejected file keeps the previous table: its generation is the one still enforced.
            if (rulesEvent.Generation is { } generation)
            {
                _generation = generation;
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
        }
    }

    public void EventSeen(DateTimeOffset now)
    {
        lock (_gate)
        {
            _lastEventUtc = now;
        }
    }

    /// <summary>The extension is connected, or said hello within <see cref="HelloLifetime"/>.</summary>
    public bool HasRecentHello(DateTimeOffset now)
    {
        lock (_gate)
        {
            return _lastHelloUtc is { } hello && (_connections > 0 || now - hello <= HelloLifetime);
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
}
