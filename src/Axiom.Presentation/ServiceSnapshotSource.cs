// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;

namespace Axiom.Presentation;

/// <summary>Snapshot source backed by the Windows service pipe. The UI never reads the service DB.</summary>
public sealed class ServiceSnapshotSource(IServiceRequestClient client) : IConnectionSnapshotSource
{
    public string Name => "Service (Named Pipe)";

    public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

    public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
        client.SendAsync<ConnectionSnapshot>(IpcCommandTypes.Snapshot, payload: null, cancellationToken);
}
