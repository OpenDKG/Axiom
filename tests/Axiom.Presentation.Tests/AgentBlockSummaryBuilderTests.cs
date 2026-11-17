// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class AgentBlockSummaryBuilderTests
{
    private static AgentEvidenceEvent Event(
        string framework,
        string eventType,
        string errorCode = "",
        string tool = "Bash") =>
        new(DateTimeOffset.UtcNow, framework, eventType, tool, "x", "ok", 0, errorCode);

    [Fact]
    public void Counts_blocks_by_harness_and_reason()
    {
        var summary = AgentBlockSummaryBuilder.Build(
        [
            Event("claude", "GUARD_BLOCKED", "read"),
            Event("claude", "GUARD_BLOCKED", "read"),
            Event("claude", "GUARD_BLOCKED", "escalation"),
            Event("codex", "GUARD_BLOCKED", "credential-store"),
            Event("codex", "GUARD_ALLOWED"),
            Event("codex", "GUARD_FAILED"),
        ]);

        Assert.Equal(6, summary.TotalEvents);
        Assert.Equal(4, summary.Blocked);
        Assert.Equal(1, summary.Allowed);
        Assert.Equal(1, summary.Failed);
        Assert.True(summary.HasBlocks);

        Assert.Equal(2, summary.HarnessCount);
        Assert.Equal(3, summary.ReasonCount);
        Assert.Equal("claude", summary.ByHarness[0].Label);
        Assert.Equal(3, summary.ByHarness[0].Count);

        var read = Assert.Single(summary.ByReason, bar => bar.Label == "protected read");
        Assert.Equal(2, read.Count);
        var store = Assert.Single(summary.ByReason, bar => bar.Label == "credential store");
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public void Unknown_reason_and_empty_evidence_are_handled()
    {
        Assert.Equal(AgentBlockSummary.Empty, AgentBlockSummaryBuilder.Build([]));

        var summary = AgentBlockSummaryBuilder.Build(
        [
            Event("", "GUARD_BLOCKED"),
            Event("windsurf", "GUARD_BLOCKED", "unknown-code"),
        ]);

        Assert.Equal(2, summary.Blocked);
        Assert.Contains(summary.ByHarness, bar => bar.Label == "unknown");
        Assert.Contains(summary.ByReason, bar => bar.Label == "other" && bar.Count == 2);
        Assert.Equal(2, summary.HarnessCount);
        Assert.Equal(1, summary.ReasonCount);
        Assert.True(summary.HasBlocks);
    }
}
