// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Blackbox;

namespace Axiom.Presentation;

/// <summary>
/// Session and activity counting for the agents dashboard. The audit trail records one row per
/// tool call, API call and file access; counting rows in the <c>sessions</c> category showed 0 even
/// when hundreds of agent sessions were recorded, because many hosts never emit
/// <c>session_start</c>/<c>session_end</c>. A distinct session id is the honest number.
/// </summary>
public static class AgentActivityMetrics
{
    /// <summary>Distinct non-empty session ids across the supplied audit rows.</summary>
    public static int CountSessions(IEnumerable<BlackboxAuditEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        var sessions = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            if (!string.IsNullOrWhiteSpace(entry.Session))
            {
                sessions.Add(entry.Session.Trim());
            }
        }

        return sessions.Count;
    }
}
