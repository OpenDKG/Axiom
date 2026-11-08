// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>Grouped connections for one executable identity in the Connections page.</summary>
public sealed record ConnectionAppGroup(
    string Key,
    string Name,
    string Path,
    IReadOnlyList<ConnectionRow> Rows,
    long BytesSent,
    long BytesReceived,
    DateTimeOffset? MeasuredSinceUtc)
{
    public int SocketCount => Rows.Count;

    public long TotalBytes => BytesSent + BytesReceived;

    public bool HasMeasurement =>
        MeasuredSinceUtc is not null || Rows.Any(row => row.ObservedBytesSent is not null);

    public string CountText => $"{SocketCount} socket{(SocketCount == 1 ? string.Empty : "s")}";

    public string ProtocolText =>
        $"{Rows.Count(row => row.ProtocolText == "TCP")} TCP · {Rows.Count(row => row.ProtocolText == "UDP")} UDP";

    public string PathText => Path.Length == 0 ? "Executable path not readable" : Path;

    public string TrafficText => HasMeasurement
        ? $"↑ {ByteFormatter.Megabytes(BytesSent)} · ↓ {ByteFormatter.Megabytes(BytesReceived)}"
        : "traffic not measured";

    public string TrafficTooltip => MeasuredSinceUtc is { } since
        ? $"TCP payload bytes measured since {since.ToLocalTime():HH:mm:ss}.\n" +
          "UDP and connections shorter than one poll are not included."
        : "Per-connection TCP statistics are unavailable in this process.";
}
