// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class AgentBlockAlertPolicyTests
{
    [Fact]
    public void History_before_the_baseline_never_alerts()
    {
        var policy = new AgentBlockAlertPolicy();
        var now = new DateTimeOffset(2026, 11, 17, 16, 0, 0, TimeSpan.Zero);

        Assert.Null(policy.Observe(1400, now));
    }

    [Fact]
    public void A_new_block_alerts_with_the_agent_sample()
    {
        var policy = new AgentBlockAlertPolicy();
        var now = new DateTimeOffset(2026, 11, 17, 16, 0, 0, TimeSpan.Zero);
        policy.MarkInitialized();

        var alert = Assert.IsType<AgentBlockAlert>(policy.Observe(1, now, "codex read ~/.ssh/id_rsa"));

        Assert.Equal(1, alert.Count);
        Assert.Contains("codex", alert.Message);
        Assert.Contains("blocked an agent action", alert.Message);
    }

    [Fact]
    public void Blocks_inside_the_cooldown_are_counted_into_the_next_alert()
    {
        var policy = new AgentBlockAlertPolicy();
        var now = new DateTimeOffset(2026, 11, 17, 16, 0, 0, TimeSpan.Zero);
        policy.MarkInitialized();

        Assert.NotNull(policy.Observe(1, now));
        Assert.Null(policy.Observe(3, now.AddMinutes(1)));
        Assert.Null(policy.Observe(2, now.AddMinutes(4)));

        var next = Assert.IsType<AgentBlockAlert>(policy.Observe(1, now.AddMinutes(5)));

        Assert.Equal(6, next.Count); // 3 + 2 accumulated + 1 new
        Assert.Contains("6 agent actions", next.Message);
    }

    [Fact]
    public void Zero_or_negative_counts_are_ignored()
    {
        var policy = new AgentBlockAlertPolicy();
        policy.MarkInitialized();

        Assert.Null(policy.Observe(0, DateTimeOffset.UtcNow));
        Assert.Null(policy.Observe(-2, DateTimeOffset.UtcNow));
    }
}
