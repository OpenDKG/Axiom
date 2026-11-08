// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;

namespace Axiom.Contracts.Monitoring;

/// <summary>One read-only capture of the host socket tables.</summary>
public sealed record ConnectionSnapshot
{
    public required DateTimeOffset CapturedUtc { get; init; }

    public required IReadOnlyList<LiveConnection> Connections { get; init; }

    /// <summary>Distinct processes that own at least one socket in this capture.</summary>
    public required int ProcessCount { get; init; }

    public required string SourceName { get; init; }

    /// <summary>Known blind spots of this capture, shown to the operator instead of hidden.</summary>
    public IReadOnlyList<string> Limitations { get; init; } = [];

    /// <summary>
    /// Cumulative TCP traffic per executable, accumulated by the service across polls. Empty when
    /// the active source cannot measure bytes.
    /// </summary>
    public IReadOnlyList<AppTrafficTotals> AppTraffic { get; init; } = [];
}
