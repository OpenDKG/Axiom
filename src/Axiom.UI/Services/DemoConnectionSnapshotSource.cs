// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;

namespace Axiom.UI.Services;

/// <summary>Demo source used only when the UI runs without a live host (design/demo shell).</summary>
public sealed class DemoConnectionSnapshotSource : IConnectionSnapshotSource
{
    private readonly IReadOnlyList<LiveConnection> _rows = DemoDataFactory.CreateConnections();

    public string Name => "Demo generator (no OS telemetry)";

    public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

    public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(new ConnectionSnapshot
        {
            CapturedUtc = DateTimeOffset.UtcNow,
            Connections = _rows,
            ProcessCount = _rows.Select(row => row.ProcessId).Distinct().Count(),
            SourceName = Name,
            Limitations =
            [
                "Demo rows only: no socket, process or interface was read.",
                "Start the Axiom desktop app for the real IP Helper inventory.",
            ],
        });
    }
}
