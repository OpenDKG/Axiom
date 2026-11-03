// SPDX-License-Identifier: GPL-3.0-or-later
namespace LocalFirewall.Contracts.Monitoring;

/// <summary>
/// A single point of an upload/download series. Values are always estimates of payload bytes
/// reported by a collector, never wire bytes and never an ISP measurement.
/// </summary>
public readonly record struct TrafficSample(DateTimeOffset TimestampUtc, long UploadBytes, long DownloadBytes);
