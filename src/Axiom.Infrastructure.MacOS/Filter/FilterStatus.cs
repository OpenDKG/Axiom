// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.MacOS.Filter;

/// <summary>
/// Liveness of the AxiomFilter system extension as seen on the flow-event socket: connection
/// count, the last <c>filter.hello</c> (version and the rules generation it loaded) and the last
/// event of any kind. Thread-safe.
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

    /// <summary>Rules generation reported by the extension in its last hello.</summary>
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

    public void Hello(string? version, long? generation, DateTimeOffset now)
    {
        lock (_gate)
        {
            _lastHelloUtc = now;
            _lastEventUtc = now;
            _version = version;
            _generation = generation;
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
