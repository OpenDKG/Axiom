// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Blackbox;

/// <summary>Schedules Axiom's optional catch-up requests to the Blackbox dashboard.</summary>
public static class BlackboxAutoSyncSchedule
{
    public const string EnabledStatus = "Auto-sync is on; checks about once an hour for new verified assets.";

    private const string PreviousEnabledStatus = "Auto-sync is on; checks every 15 minutes for new verified assets.";

    private static readonly TimeSpan MinimumInterval = TimeSpan.FromHours(1);

    public static bool IsDue(DateTimeOffset lastAttemptUtc, DateTimeOffset nowUtc) =>
        nowUtc - lastAttemptUtc >= MinimumInterval;

    public static string EnabledStatusAfterLoad(string? lastStatus) =>
        string.IsNullOrWhiteSpace(lastStatus) || string.Equals(lastStatus, PreviousEnabledStatus, StringComparison.Ordinal)
            ? EnabledStatus
            : lastStatus;
}
