// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// Describes how old the newest recorded agent event is. A dashboard that still answers but
/// receives no events looks like a frozen page; the UI uses this to say so and to point at the
/// agent hooks instead of pretending the data is live.
/// </summary>
public static class ActivityFreshness
{
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(15);

    public static bool IsStale(DateTimeOffset? newestUtc, DateTimeOffset nowUtc) =>
        newestUtc is { } newest && nowUtc - newest > StaleAfter;

    public static bool IsStale(DateTimeOffset? newestUtc, DateTimeOffset nowUtc, bool anyAgentRunning) =>
        anyAgentRunning && IsStale(newestUtc, nowUtc);

    public static string Describe(DateTimeOffset? newestUtc, DateTimeOffset nowUtc) =>
        Describe(newestUtc, nowUtc, anyAgentRunning: true);

    public static string Describe(DateTimeOffset? newestUtc, DateTimeOffset nowUtc, bool anyAgentRunning)
    {
        if (newestUtc is not { } newest)
        {
            return "No recorded agent event yet.";
        }

        var local = newest.ToLocalTime();
        var age = nowUtc - newest;
        if (age < TimeSpan.Zero)
        {
            age = TimeSpan.Zero;
        }

        if (age > StaleAfter)
        {
            if (!anyAgentRunning)
            {
                return $"Last agent activity at {local:HH:mm} ({Format(age)} ago) · no active agent session right now.";
            }

            return $"No new agent activity since {local:HH:mm} ({Format(age)} ago). " +
                   "The Blackbox dashboard may be stalled or the agent hooks are not loaded; " +
                   "an agent keeps the hook it loaded at start, so restart it (especially after an " +
                   "Axiom update) or use Install/repair agent hooks on the Agents page.";
        }

        return $"Newest agent event {local:HH:mm} ({Format(age)} ago).";
    }

    private static string Format(TimeSpan age) => age.TotalHours >= 1
        ? $"{(int)age.TotalHours}h {age.Minutes:00}m"
        : age.TotalMinutes >= 1
            ? $"{(int)age.TotalMinutes} min"
            : "<1 min";
}
