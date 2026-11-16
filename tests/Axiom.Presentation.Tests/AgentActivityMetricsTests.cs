// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Blackbox;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class AgentActivityMetricsTests
{
    private static BlackboxAuditEntry Entry(string session, string @event = "pre_tool_call") =>
        new(
            DateTimeOffset.UtcNow,
            @event,
            "hermes",
            session,
            "Bash",
            string.Empty,
            string.Empty,
            "info",
            string.Empty,
            string.Empty);

    [Fact]
    public void Counts_distinct_non_empty_sessions_not_session_events()
    {
        var entries = new[]
        {
            Entry("s1"),
            Entry("s1"),
            Entry("s2"),
            Entry("s2"),
            Entry(" "),
            Entry(string.Empty),
            Entry("s3", "session_start"),
        };

        Assert.Equal(3, AgentActivityMetrics.CountSessions(entries));
        Assert.Equal(1, entries.Count(entry => entry.Category == "sessions"));
    }

    [Fact]
    public void Empty_audit_has_no_sessions()
    {
        Assert.Equal(0, AgentActivityMetrics.CountSessions([]));
    }
}
