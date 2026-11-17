// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Text.Json;
using Axiom.Contracts.History;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class HistoryEventExportTests
{
    [Fact]
    public void Export_carries_the_same_fields_as_the_csv_export()
    {
        var row = new HistoryRow
        {
            AppDisplayName = "browser.exe",
            AppPath = @"C:\Apps\browser.exe",
            ProcessId = 4242,
            Protocol = "TCP",
            LocalEndpoint = "127.0.0.1:50000",
            RemoteEndpoint = "1.1.1.1:443",
            Direction = "Outbound",
            State = "Established",
            Quality = "Live",
            FirstSeenUtc = new DateTimeOffset(2026, 11, 17, 9, 0, 0, TimeSpan.Zero),
            LastSeenUtc = new DateTimeOffset(2026, 11, 17, 9, 5, 0, TimeSpan.Zero),
        };

        var json = HistoryEventExport.ToJson([row], new DateTimeOffset(2026, 11, 17, 9, 30, 0, TimeSpan.Zero));

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal(HistoryEventExport.Schema, root.GetProperty("schema").GetString());
        Assert.Equal(1, root.GetProperty("count").GetInt32());

        var exported = Assert.Single(root.GetProperty("events").EnumerateArray());
        Assert.Equal("network", exported.GetProperty("type").GetString());
        Assert.Equal("browser.exe", exported.GetProperty("app").GetString());
        Assert.Equal(@"C:\Apps\browser.exe", exported.GetProperty("path").GetString());
        Assert.Equal(4242, exported.GetProperty("pid").GetInt32());
        Assert.Equal("TCP", exported.GetProperty("protocol").GetString());
        Assert.Equal("127.0.0.1:50000", exported.GetProperty("local").GetString());
        Assert.Equal("1.1.1.1:443", exported.GetProperty("remote").GetString());
        Assert.Equal("Outbound", exported.GetProperty("direction").GetString());
        Assert.Equal("Established", exported.GetProperty("state").GetString());
        Assert.Equal("Live", exported.GetProperty("quality").GetString());
        Assert.Equal("2026-11-17T09:00:00.0000000+00:00", exported.GetProperty("firstSeenUtc").GetString());
    }

    [Fact]
    public void Empty_history_exports_an_empty_array()
    {
        var json = HistoryEventExport.ToJson([], DateTimeOffset.UnixEpoch);

        using var document = JsonDocument.Parse(json);
        Assert.Equal(0, document.RootElement.GetProperty("count").GetInt32());
        Assert.Equal(0, document.RootElement.GetProperty("events").GetArrayLength());
    }
}
