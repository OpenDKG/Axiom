// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>One labelled block count for the agents page chart.</summary>
public sealed record AgentBlockBar(string Label, int Count);

/// <summary>Totals and breakdowns of guard decisions, built from the local evidence store.</summary>
public sealed record AgentBlockSummary(
    int TotalEvents,
    int Blocked,
    int Allowed,
    int Failed,
    int HarnessCount,
    int ReasonCount,
    IReadOnlyList<AgentBlockBar> ByHarness,
    IReadOnlyList<AgentBlockBar> ByReason)
{
    public static AgentBlockSummary Empty { get; } = new(0, 0, 0, 0, 0, 0, [], []);

    public bool HasBlocks => Blocked > 0;
}

/// <summary>
/// Aggregates <see cref="AgentEvidenceEvent"/> rows into the numbers the agents page shows. A
/// blocked event is <c>GUARD_BLOCKED</c>; failures are <c>GUARD_FAILED</c>/<c>GUARD_TIMEOUT</c>.
/// </summary>
public static class AgentBlockSummaryBuilder
{
    private static readonly Dictionary<string, string> ReasonLabels =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["escalation"] = "escalation",
            ["read"] = "protected read",
            ["tamper"] = "guard tamper",
            ["credential-store"] = "credential store",
            ["exfiltration"] = "exfiltration",
            ["permissions"] = "permissions",
            ["injection-heuristic"] = "prompt injection",
            ["delete"] = "protected delete",
            ["execution"] = "protected launch",
        };

    public static AgentBlockSummary Build(IEnumerable<AgentEvidenceEvent> events, int maxBars = 8)
    {
        ArgumentNullException.ThrowIfNull(events);

        var total = 0;
        var blocked = 0;
        var allowed = 0;
        var failed = 0;
        var byHarness = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var byReason = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in events)
        {
            total++;
            if (item.IsFailure)
            {
                failed++;
            }

            if (!string.Equals(item.EventType, "GUARD_BLOCKED", StringComparison.OrdinalIgnoreCase))
            {
                if (string.Equals(item.EventType, "GUARD_ALLOWED", StringComparison.OrdinalIgnoreCase))
                {
                    allowed++;
                }

                continue;
            }

            blocked++;
            var harness = string.IsNullOrWhiteSpace(item.Framework) ? "unknown" : item.Framework.Trim();
            byHarness[harness] = byHarness.TryGetValue(harness, out var count) ? count + 1 : 1;

            var code = (item.ErrorCode ?? string.Empty).Trim();
            var reason = ReasonLabels.TryGetValue(code, out var label) && code.Length > 0 ? label : "other";
            byReason[reason] = byReason.TryGetValue(reason, out var hits) ? hits + 1 : 1;
        }

        return new AgentBlockSummary(
            total,
            blocked,
            allowed,
            failed,
            byHarness.Count,
            byReason.Count,
            Top(byHarness, maxBars),
            Top(byReason, maxBars));
    }

    private static AgentBlockBar[] Top(Dictionary<string, int> counts, int maxBars) =>
        counts
            .OrderByDescending(pair => pair.Value)
            .ThenBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(1, maxBars))
            .Select(pair => new AgentBlockBar(pair.Key, pair.Value))
            .ToArray();
}
