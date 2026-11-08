// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Monitoring;

/// <summary>
/// Cumulative TCP traffic attributed to one executable identity since the service started
/// observing it. Values come from per-connection extended TCP statistics; UDP and connections
/// shorter than one poll are not included.
/// </summary>
public sealed record AppTrafficTotals(
    string Key,
    string AppName,
    string AppPath,
    long BytesSent,
    long BytesReceived,
    DateTimeOffset SinceUtc,
    DateTimeOffset UpdatedUtc)
{
    public long TotalBytes => BytesSent + BytesReceived;
}
