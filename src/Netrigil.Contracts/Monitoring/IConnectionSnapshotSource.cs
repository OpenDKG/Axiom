// SPDX-License-Identifier: GPL-3.0-or-later
using Netrigil.Contracts.Monitoring;

namespace Netrigil.Contracts.Monitoring;

/// <summary>
/// Read-only snapshot of the host's TCP/UDP sockets with process attribution. Implemented by
/// <c>Netrigil.Infrastructure.Windows</c>; the UI only sees this contract.
/// </summary>
public interface IConnectionSnapshotSource
{
    /// <summary>Short, user-presentable source name, for example "IP Helper (TCP/UDP v4+v6)".</summary>
    string Name { get; }

    /// <summary>Polling cadence this source is designed for.</summary>
    TimeSpan PollInterval { get; }

    Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken);
}
