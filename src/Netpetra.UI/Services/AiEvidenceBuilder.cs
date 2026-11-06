// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using Netpetra.Contracts.Ai;
using Netpetra.Contracts.Monitoring;

namespace Netpetra.UI.Services;

/// <summary>
/// Converts a bounded snapshot into evidence. Local paths are reduced to file names by default;
/// packet contents, credentials and agent history are never collected.
/// </summary>
public static class AiEvidenceBuilder
{
    public static AiEvidencePackage Build(
        IReadOnlyList<LiveConnection> connections,
        string sourceName,
        IReadOnlyList<string> limitations,
        int maxConnections,
        bool redactPaths)
    {
        ArgumentNullException.ThrowIfNull(connections);

        var limit = Math.Clamp(maxConnections, 1, 50);
        var selected = connections
            .OrderByDescending(connection => connection.IsNew)
            .ThenBy(connection => connection.IsLoopback)
            .ThenBy(connection => connection.AppDisplayName, StringComparer.OrdinalIgnoreCase)
            .Take(limit)
            .ToArray();

        var evidence = new List<AiEvidenceConnection>(selected.Length);
        for (var index = 0; index < selected.Length; index++)
        {
            var connection = selected[index];
            evidence.Add(new AiEvidenceConnection(
                $"connection-{index + 1}",
                connection.AppDisplayName,
                redactPaths && connection.AppPath.Length > 0
                    ? Path.GetFileName(connection.AppPath)
                    : connection.AppPath.Length > 0 ? connection.AppPath : null,
                connection.ProcessId,
                connection.Protocol.ToString(),
                connection.Direction.ToString(),
                connection.State,
                connection.LocalEndpoint,
                string.IsNullOrWhiteSpace(connection.RemoteEndpoint) ? "unknown" : connection.RemoteEndpoint,
                connection.IsLoopback,
                connection.IsNew,
                connection.FirstObservedUtc,
                connection.Quality.ToString()));
        }

        return new AiEvidencePackage(
            "1",
            DateTimeOffset.UtcNow,
            sourceName,
            redactPaths ? "paths-redacted" : "full-path",
            limitations,
            evidence);
    }

    public static string DescribeConnectionCount(AiEvidencePackage evidence) =>
        $"{evidence.Connections.Count.ToString(CultureInfo.InvariantCulture)} bounded connection(s)";
}
