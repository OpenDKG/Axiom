// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using Axiom.Contracts.Ai;
using Axiom.Contracts.Monitoring;

namespace Axiom.UI.Services;

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
        bool redactPaths,
        AiEvidenceBaseline? baseline = null)
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
        var capturedUtc = DateTimeOffset.UtcNow;
        for (var index = 0; index < selected.Length; index++)
        {
            var connection = selected[index];
            var item = new AiEvidenceConnection(
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
                connection.Quality.ToString());
            evidence.Add(AiEvidenceContext.Enrich(item, connection, capturedUtc));
            var appKey = AiEvidenceBaselineCollector.AppKey(
                connection.AppPath,
                connection.AppDisplayName,
                connection.ProcessId);
            var flowKey = AiEvidenceBaselineCollector.FlowKey(
                appKey,
                connection.Protocol.ToString(),
                connection.RemoteEndpoint,
                connection.Direction.ToString());

            if (baseline is not null)
            {
                baseline.Flows.TryGetValue(flowKey, out var flow);
                baseline.Apps.TryGetValue(appKey, out var app);
                evidence[^1] = evidence[^1] with
                {
                    BaselineFlowRows = flow?.Rows ?? 0,
                    BaselineFirstSeenUtc = flow?.FirstSeenUtc,
                    BaselineLastSeenUtc = flow?.LastSeenUtc,
                    BaselineAppFlowRows = app?.Rows ?? 0,
                    BaselineTypicalRemotes = app?.TypicalRemotes ?? [],
                };
            }
        }

        var combinedLimitations = limitations
            .Concat(AiEvidenceContext.KnownLimitations())
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return new AiEvidencePackage(
            "2",
            capturedUtc,
            sourceName,
            redactPaths ? "paths-redacted" : "full-path",
            combinedLimitations,
            evidence)
        {
            Host = AiEvidenceContext.CollectHost(),
            BaselineWindowDays = baseline?.WindowDays ?? 0,
            BaselineRowsConsidered = baseline?.RowsConsidered ?? 0,
            BaselineTotalCount = baseline?.TotalCount ?? 0,
            BaselineTruncated = baseline?.Truncated ?? false,
            BaselineNote = baseline?.Note ?? "Local flow history baseline was not available.",
        };
    }

    public static string DescribeConnectionCount(AiEvidencePackage evidence) =>
        $"{evidence.Connections.Count.ToString(CultureInfo.InvariantCulture)} bounded connection(s)";
}
