// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.Contracts.Ipc;
using Netpetra.Contracts.Monitoring;

namespace Netpetra.UI.Services;

/// <summary>Snapshot source backed by the Windows service pipe (FND-003).</summary>
public sealed class ServiceSnapshotSource(ServicePipeClient client) : IConnectionSnapshotSource
{
    public string Name => "Service (Named Pipe)";

    public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

    public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
        client.SendAsync<ConnectionSnapshot>(IpcCommandTypes.Snapshot, payload: null, cancellationToken);
}
