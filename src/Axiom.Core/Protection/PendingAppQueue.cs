// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Protection;

namespace Axiom.Core.Protection;

/// <summary>
/// Maintains the durable Shield ask queue. A detected application remains pending after its socket
/// ends, until the operator chooses Block, Allow or Dismiss. A dismissed application returns only
/// when a new connection is observed after the dismissal.
/// </summary>
public static class PendingAppLedger
{
    public const int MaxPending = 50;
    private const int MaxDismissals = 200;
    private static readonly TimeSpan DismissalRetention = TimeSpan.FromDays(30);

    public static PendingQueueResult Merge(
        IReadOnlyList<ProtectionPendingApp>? existing,
        IReadOnlyList<ProtectionDismissal>? dismissals,
        IReadOnlyList<ProtectionPendingApp> detected,
        IReadOnlyCollection<ProtectionDecision>? decisions,
        DateTimeOffset now)
    {
        var decided = new HashSet<string>(
            (decisions ?? []).Select(decision => decision.AppPath),
            StringComparer.OrdinalIgnoreCase);

        var pending = new Dictionary<string, ProtectionPendingApp>(StringComparer.OrdinalIgnoreCase);
        var changed = false;

        var dismissalMap = new Dictionary<string, ProtectionDismissal>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in dismissals ?? [])
        {
            if (decided.Contains(item.AppPath) || now - item.DismissedUtc > DismissalRetention)
            {
                changed = true;
                continue;
            }

            if (!dismissalMap.TryGetValue(item.AppPath, out var current) ||
                item.DismissedUtc > current.DismissedUtc)
            {
                dismissalMap[item.AppPath] = item;
            }
        }

        var detectedMap = new Dictionary<string, ProtectionPendingApp>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in detected)
        {
            if (!decided.Contains(item.AppPath))
            {
                detectedMap[item.AppPath] = item;
            }
        }

        foreach (var item in existing ?? [])
        {
            if (decided.Contains(item.AppPath))
            {
                changed = true;
                continue;
            }

            if (dismissalMap.TryGetValue(item.AppPath, out var dismissal))
            {
                var hasNewConnection = detectedMap.TryGetValue(item.AppPath, out var current) &&
                                       NewestConnection(current) > dismissal.DismissedUtc;
                if (!hasNewConnection)
                {
                    changed = true;
                    continue;
                }
            }

            var isConnected = detectedMap.ContainsKey(item.AppPath);
            pending[item.AppPath] = item with { IsConnected = isConnected };
            if (item.IsConnected != isConnected || item.LastSeenUtc is null)
            {
                changed = true;
            }
        }

        foreach (var item in detectedMap.Values)
        {
            if (dismissalMap.TryGetValue(item.AppPath, out var dismissal))
            {
                if (NewestConnection(item) <= dismissal.DismissedUtc)
                {
                    continue;
                }

                dismissalMap.Remove(item.AppPath);
                changed = true;
            }

            if (pending.TryGetValue(item.AppPath, out var old))
            {
                var first = old.FirstObservedUtc < item.FirstObservedUtc
                    ? old.FirstObservedUtc
                    : item.FirstObservedUtc;
                pending[item.AppPath] = item with { FirstObservedUtc = first };
                if (!old.IsConnected || old.LastSeenUtc is null)
                {
                    changed = true;
                }
            }
            else
            {
                pending[item.AppPath] = item;
                changed = true;
            }
        }

        var ordered = pending.Values
            .OrderByDescending(item => item.IsConnected)
            .ThenByDescending(item => item.IsAgent)
            .ThenByDescending(item => item.FirstObservedUtc)
            .ThenBy(item => item.AppPath, StringComparer.OrdinalIgnoreCase)
            .Take(MaxPending)
            .ToArray();

        var keptDismissals = dismissalMap.Values
            .OrderByDescending(item => item.DismissedUtc)
            .Take(MaxDismissals)
            .ToArray();

        if (ordered.Length != pending.Count || keptDismissals.Length != dismissalMap.Count)
        {
            changed = true;
        }

        return new PendingQueueResult(ordered, keptDismissals, changed);
    }

    private static DateTimeOffset NewestConnection(ProtectionPendingApp item) =>
        item.LatestConnectionFirstObservedUtc ?? item.FirstObservedUtc;
}

public sealed record PendingQueueResult(
    IReadOnlyList<ProtectionPendingApp> Pending,
    IReadOnlyList<ProtectionDismissal> Dismissals,
    bool Changed);
