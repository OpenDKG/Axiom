// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Core.Enforcement;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class JsonLinesProcessSpawnSinkTests
{
    private static readonly DateTimeOffset At = new(2026, 11, 15, 11, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Each_audit_becomes_one_json_line_with_the_decision()
    {
        var writer = new StringWriter();
        var sink = new JsonLinesProcessSpawnSink(writer);

        sink.Record(new ProcessSpawnAudit(
            new ProcessSpawnEvent(100, 50, @"C:\Users\lab\Downloads\dropper.exe", @"C:\Users\lab\opencode.exe", At),
            new ProcessSpawnDecision(ProcessSpawnVerdict.Block, "agent spawned an executable from a download or staging folder")));
        sink.Record(new ProcessSpawnAudit(
            new ProcessSpawnEvent(101, 50, @"C:\Windows\System32\notepad.exe", @"C:\Users\lab\opencode.exe", At),
            new ProcessSpawnDecision(ProcessSpawnVerdict.Record, "agent process spawned a child process")));

        var lines = writer.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);

        using var first = JsonDocument.Parse(lines[0]);
        var root = first.RootElement;
        Assert.Equal(100, root.GetProperty("pid").GetInt32());
        Assert.Equal(50, root.GetProperty("parentPid").GetInt32());
        Assert.Equal(@"C:\Users\lab\Downloads\dropper.exe", root.GetProperty("image").GetString());
        Assert.Equal("block", root.GetProperty("verdict").GetString());
        Assert.Contains("staging", root.GetProperty("reason").GetString(), StringComparison.OrdinalIgnoreCase);

        using var second = JsonDocument.Parse(lines[1]);
        Assert.Equal("record", second.RootElement.GetProperty("verdict").GetString());
    }

    [Fact]
    public void A_null_audit_is_rejected()
    {
        var sink = new JsonLinesProcessSpawnSink(new StringWriter());

        Assert.Throws<ArgumentNullException>(() => sink.Record(null!));
    }
}
