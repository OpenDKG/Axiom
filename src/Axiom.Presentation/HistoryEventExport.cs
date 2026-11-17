// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Contracts.History;

namespace Axiom.Presentation;

/// <summary>
/// Read-only JSON export of the network event history (FND-005). It carries the same fields as the
/// CSV export so an operator can archive or diff events without a database; it never reads packet
/// payloads and adds no machine identifiers.
/// </summary>
public static class HistoryEventExport
{
    public const string Schema = "axiom.network-events.v1";

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };

    public static string ToJson(IReadOnlyList<HistoryRow> rows, DateTimeOffset exportedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(rows);

        var payload = new
        {
            schema = Schema,
            exportedAtUtc = exportedAtUtc.ToUniversalTime().ToString("O"),
            count = rows.Count,
            events = rows.Select(row => new
            {
                type = "network",
                app = row.AppDisplayName,
                path = row.AppPath,
                pid = row.ProcessId,
                protocol = row.Protocol,
                local = row.LocalEndpoint,
                remote = row.RemoteEndpoint,
                direction = row.Direction,
                state = row.State,
                quality = row.Quality,
                firstSeenUtc = row.FirstSeenUtc.ToUniversalTime().ToString("O"),
                lastSeenUtc = row.LastSeenUtc.ToUniversalTime().ToString("O"),
            }).ToArray(),
        };

        return JsonSerializer.Serialize(payload, Options);
    }
}
