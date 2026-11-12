// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Persistence;

/// <summary>One completed or partial minute of system-wide interface throughput.</summary>
public sealed record ThroughputBucket(
    DateTimeOffset StartUtc,
    long UploadBytes,
    long DownloadBytes,
    double MeasuredSeconds);
