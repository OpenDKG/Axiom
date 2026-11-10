// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class ActivityFreshnessTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 21, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Recent_event_is_not_stale()
    {
        Assert.False(ActivityFreshness.IsStale(Now.AddMinutes(-2), Now));
    }

    [Fact]
    public void Old_event_is_stale_and_the_text_names_the_time()
    {
        var newest = Now.AddHours(-6);

        Assert.True(ActivityFreshness.IsStale(newest, Now));
        var text = ActivityFreshness.Describe(newest, Now);
        Assert.Contains("No new agent activity", text, StringComparison.Ordinal);
        Assert.Contains("6h 00m", text, StringComparison.Ordinal);
        Assert.Contains("Install/repair agent hooks", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_history_is_reported_without_a_bogus_timestamp()
    {
        Assert.False(ActivityFreshness.IsStale(null, Now));
        Assert.Equal("No recorded agent event yet.", ActivityFreshness.Describe(null, Now));
    }
}
