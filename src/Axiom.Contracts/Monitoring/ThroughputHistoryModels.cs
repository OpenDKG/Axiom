// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Monitoring;

/// <summary>
/// Request for persisted system-wide throughput. The service records one row per minute and
/// aggregates it into <see cref="BucketSeconds"/> wide points for the caller.
/// </summary>
public sealed record ThroughputHistoryQuery
{
    public required DateTimeOffset FromUtc { get; init; }

    public required DateTimeOffset ToUtc { get; init; }

    /// <summary>Aggregation width in seconds. Clamped by the service to 60..21600.</summary>
    public int BucketSeconds { get; init; } = 60;
}

/// <summary>
/// One aggregated bucket of measured interface traffic. Bytes are the observed total, and
/// <see cref="MeasuredSeconds"/> is how much of the bucket was actually sampled, so a caller can
/// show an honest average rate and keep gaps as gaps.
/// </summary>
public sealed record ThroughputPoint
{
    public required DateTimeOffset StartUtc { get; init; }

    public required long UploadBytes { get; init; }

    public required long DownloadBytes { get; init; }

    public required double MeasuredSeconds { get; init; }
}

/// <summary>Persisted throughput for one window, oldest point first.</summary>
public sealed record ThroughputHistory
{
    public required IReadOnlyList<ThroughputPoint> Points { get; init; }

    public required int BucketSeconds { get; init; }

    public required DateTimeOffset QueriedUtc { get; init; }

    /// <summary>Why the history may be short: service start time, retention, or a read error.</summary>
    public string? Detail { get; init; }
}
