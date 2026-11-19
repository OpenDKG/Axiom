// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Blackbox;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class BlackboxAutoSyncScheduleTests
{
    [Fact]
    public void Optional_sync_waits_for_sixty_minutes_after_the_last_attempt()
    {
        var lastAttempt = new DateTimeOffset(2026, 11, 19, 13, 0, 0, TimeSpan.Zero);

        Assert.True(BlackboxAutoSyncSchedule.IsDue(DateTimeOffset.MinValue, lastAttempt));
        Assert.False(BlackboxAutoSyncSchedule.IsDue(lastAttempt, lastAttempt.AddMinutes(15)));
        Assert.False(BlackboxAutoSyncSchedule.IsDue(lastAttempt, lastAttempt.AddHours(1).AddSeconds(-1)));
        Assert.True(BlackboxAutoSyncSchedule.IsDue(lastAttempt, lastAttempt.AddHours(1)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("Auto-sync is on; checks every 15 minutes for new verified assets.")]
    public void Enabled_status_displays_the_current_interval(string? previousStatus)
    {
        Assert.Equal(BlackboxAutoSyncSchedule.EnabledStatus, BlackboxAutoSyncSchedule.EnabledStatusAfterLoad(previousStatus));
        Assert.Equal("Auto-sync requested.", BlackboxAutoSyncSchedule.EnabledStatusAfterLoad("Auto-sync requested."));
    }
}
