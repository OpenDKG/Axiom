// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.History;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class HistoryCsvTests
{
    [Fact]
    public void Fields_are_quoted_and_escaped_per_rfc_4180()
    {
        var csv = HistoryCsv.Format([Row(app: "a,b", path: "/opt/\"quoted\"", remote: "line\nbreak")]);

        Assert.StartsWith("application,path,pid", csv, StringComparison.Ordinal);
        Assert.Contains("\"a,b\"", csv, StringComparison.Ordinal);
        Assert.Contains("\"/opt/\"\"quoted\"\"\"", csv, StringComparison.Ordinal);
        Assert.Contains("\"line\nbreak\"", csv, StringComparison.Ordinal);
        Assert.Contains("\r\n", csv, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("=cmd|' /C calc'!A0")]
    [InlineData("+1+1")]
    [InlineData("-2+3")]
    [InlineData("@SUM(A1)")]
    [InlineData("\t=1")]
    public void Spreadsheet_formulas_are_neutralised(string value)
    {
        var csv = HistoryCsv.Format([Row(app: value)]);

        var line = csv.Split("\r\n")[1];
        Assert.StartsWith("'", line, StringComparison.Ordinal);
        Assert.DoesNotContain("\n" + value, csv, StringComparison.Ordinal);
    }

    [Fact]
    public void Plain_values_stay_unquoted()
    {
        var csv = HistoryCsv.Format([Row(app: "firefox", path: "/usr/lib/firefox/firefox")]);

        Assert.Contains("firefox,/usr/lib/firefox/firefox,", csv, StringComparison.Ordinal);
    }

    private static HistoryRow Row(
        string app = "app",
        string path = "/usr/bin/app",
        string remote = "203.0.113.10:443") => new()
        {
            AppDisplayName = app,
            AppPath = path,
            ProcessId = 4242,
            Protocol = "tcp",
            LocalEndpoint = "127.0.0.1:5000",
            RemoteEndpoint = remote,
            Direction = "outbound",
            State = "established",
            Quality = "complete",
            FirstSeenUtc = DateTimeOffset.UnixEpoch,
            LastSeenUtc = DateTimeOffset.UnixEpoch,
        };
}
