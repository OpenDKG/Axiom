// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using LocalFirewall.Contracts.History;

namespace LocalFirewall.UI.ViewModels;

/// <summary>Presentation wrapper for one stored flow.</summary>
public sealed class HistoryRowView(HistoryRow row)
{
    public string AppDisplayName => row.AppDisplayName;

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

    public DateTimeOffset LastSeenUtc => row.LastSeenUtc;

    public string FirstSeenText => row.FirstSeenUtc.ToLocalTime()
        .ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    public string LastSeenText => row.LastSeenUtc.ToLocalTime()
        .ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    public string RowTooltip =>
        $"{row.AppPath}\nFirst seen: {row.FirstSeenUtc:O}\nLast seen: {row.LastSeenUtc:O}";
}
