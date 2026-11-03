// SPDX-License-Identifier: GPL-3.0-or-later
using Netrigil.Contracts.Monitoring;

namespace Netrigil.Service;

/// <summary>Thread-safe holder of the latest snapshot produced by the monitoring worker.</summary>
public sealed class ConnectionSnapshotCache
{
    private ConnectionSnapshot? _latest;

    private long _revision;

    public string SourceName { get; set; } = "IP Helper (TCP/UDP v4+v6)";

    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(1);

    public string? LastError { get; private set; }

    public ConnectionSnapshot? Latest => Volatile.Read(ref _latest);

    public long Revision => Interlocked.Read(ref _revision);

    public void Update(ConnectionSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        Volatile.Write(ref _latest, snapshot);
        Interlocked.Increment(ref _revision);
        LastError = null;
    }

    public void Fail(string message) => LastError = message;
}
