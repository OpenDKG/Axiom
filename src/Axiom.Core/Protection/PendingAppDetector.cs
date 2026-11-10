// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Protection;

namespace Axiom.Core.Protection;

/// <summary>
/// Turns the live outbound inventory into the "new application" queue of the ask policy.
/// Pure and deterministic so the UI and the service agree on what is pending.
/// </summary>
public static class PendingAppDetector
{
    public const int DefaultLimit = 50;

    public static IReadOnlyList<ProtectionPendingApp> Detect(
        IEnumerable<LiveConnection>? connections,
        IReadOnlyCollection<ProtectionDecision>? decisions,
        int limit = DefaultLimit,
        DateTimeOffset? now = null)
    {
        if (connections is null || limit <= 0)
        {
            return [];
        }

        var capturedUtc = now ?? DateTimeOffset.UtcNow;
        var decisionList = (decisions ?? []).ToList();
        var decided = new HashSet<string>(
            decisionList.Select(decision => decision.AppPath),
            StringComparer.OrdinalIgnoreCase);
        var decidedFamilies = new HashSet<string>(
            decisionList.Select(decision => ProtectionPathFamily.Key(decision.AppPath)),
            StringComparer.OrdinalIgnoreCase);

        return connections
            .Where(connection =>
                !connection.IsLoopback &&
                connection.Direction == ConnectionDirection.Outbound &&
                !string.IsNullOrWhiteSpace(connection.AppPath) &&
                !decided.Contains(connection.AppPath) &&
                !decidedFamilies.Contains(ProtectionPathFamily.Key(connection.AppPath)))
            .GroupBy(connection => connection.AppPath, StringComparer.OrdinalIgnoreCase)
            .Select(group => new ProtectionPendingApp
            {
                AppPath = group.Key,
                AppName = group.First().AppDisplayName,
                SocketCount = group.Count(),
                FirstObservedUtc = group.Min(connection => connection.FirstObservedUtc),
                IsAgent = AgentExecutables.IsAgentPath(group.Key),
                RemoteEndpoints = group
                    .Select(connection => connection.RemoteEndpoint)
                    .Where(endpoint =>
                        !string.IsNullOrWhiteSpace(endpoint) &&
                        !string.Equals(endpoint, "—", StringComparison.Ordinal))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(5)
                    .ToList(),
                IsConnected = true,
                LastSeenUtc = capturedUtc,
                LatestConnectionFirstObservedUtc = group.Max(connection => connection.FirstObservedUtc),
            })
            .OrderByDescending(item => item.IsAgent)
            .ThenByDescending(item => item.FirstObservedUtc)
            .Take(limit)
            .ToList();
    }
}
