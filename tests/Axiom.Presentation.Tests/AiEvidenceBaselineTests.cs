// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.History;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class AiEvidenceBaselineTests
{
    [Fact]
    public void Baseline_aggregates_flow_rows_and_typical_remotes()
    {
        var first = DateTimeOffset.UnixEpoch;
        var last = first.AddDays(2);
        var page = new HistoryPage
        {
            Rows =
            [
                new HistoryRow
                {
                    AppDisplayName = "app.exe",
                    AppPath = @"C:\Apps\app.exe",
                    ProcessId = 42,
                    Protocol = "Tcp",
                    LocalEndpoint = "192.0.2.10:50000",
                    RemoteEndpoint = "203.0.113.10:443",
                    Direction = "Outbound",
                    State = "Established",
                    Quality = "Observed",
                    FirstSeenUtc = first,
                    LastSeenUtc = last,
                },
                new HistoryRow
                {
                    AppDisplayName = "app.exe",
                    AppPath = @"C:\Apps\app.exe",
                    ProcessId = 42,
                    Protocol = "Tcp",
                    LocalEndpoint = "192.0.2.10:50001",
                    RemoteEndpoint = "203.0.113.10:443",
                    Direction = "Outbound",
                    State = "Established",
                    Quality = "Observed",
                    FirstSeenUtc = first.AddHours(1),
                    LastSeenUtc = last.AddHours(1),
                },
            ],
            TotalCount = 2,
            DatabasePath = "test.db",
            QueriedUtc = last,
        };

        var baseline = AiEvidenceBaselineCollector.Build(page);
        var appKey = AiEvidenceBaselineCollector.AppKey(@"C:\Apps\app.exe", "app.exe", 42);
        var flowKey = AiEvidenceBaselineCollector.FlowKey(
            appKey,
            "Tcp",
            "203.0.113.10:443",
            "Outbound");

        Assert.False(baseline.Truncated);
        Assert.Equal(2, baseline.Apps[appKey].Rows);
        Assert.Equal(2, baseline.Flows[flowKey].Rows);
        Assert.Equal(first, baseline.Flows[flowKey].FirstSeenUtc);
        Assert.Equal(last.AddHours(1), baseline.Flows[flowKey].LastSeenUtc);
        Assert.Contains("203.0.113.10:443", baseline.Apps[appKey].TypicalRemotes);
    }

    [Fact]
    public void Baseline_marks_truncated_history()
    {
        var page = new HistoryPage
        {
            Rows = [],
            TotalCount = 6000,
            DatabasePath = "test.db",
            QueriedUtc = DateTimeOffset.UtcNow,
        };

        var baseline = AiEvidenceBaselineCollector.Build(page);

        Assert.True(baseline.Truncated);
        Assert.Contains("6000", baseline.Note, StringComparison.Ordinal);
    }
}
