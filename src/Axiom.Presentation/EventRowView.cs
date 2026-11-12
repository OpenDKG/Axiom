// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Contracts.History;

namespace Axiom.Presentation;

/// <summary>Presentation wrapper for one stored event (currently network flows).</summary>
public sealed class EventRowView(HistoryRow row)
{
    public string TypeText => "Network";

    public string AppDisplayName => row.AppDisplayName;

    public string AppPath => row.AppPath;

    public int ProcessId => row.ProcessId;

    public string Protocol => row.Protocol.ToUpperInvariant();

    public string LocalEndpoint => row.LocalEndpoint;

    public string RemoteEndpoint => row.RemoteEndpoint;

    public string DirectionText => row.Direction switch
    {
        "Outbound" => "Out",
        "Inbound" => "In",
        _ => "?",
    };

    public string State => row.State;

    public string Quality => row.Quality;

    public DateTimeOffset FirstSeenUtc => row.FirstSeenUtc;

    public DateTimeOffset LastSeenUtc => row.LastSeenUtc;

    public string FirstSeenText => row.FirstSeenUtc.ToLocalTime()
        .ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    public string LastSeenText => row.LastSeenUtc.ToLocalTime()
        .ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    public string RowTooltip =>
        $"{row.AppPath}\nFirst seen: {row.FirstSeenUtc:O}\nLast seen: {row.LastSeenUtc:O}";

    public string Details =>
        $"Application: {row.AppDisplayName} (PID {row.ProcessId})\n" +
        $"Executable: {(string.IsNullOrWhiteSpace(row.AppPath) ? "—" : row.AppPath)}\n" +
        $"Flow: {Protocol} · {DirectionText} · {LocalEndpoint} -> {RemoteEndpoint}\n" +
        $"State: {State} · Attribution: {Quality}\n" +
        $"First seen: {row.FirstSeenUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} ({row.FirstSeenUtc:O})\n" +
        $"Last seen: {row.LastSeenUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} ({row.LastSeenUtc:O})";
}
