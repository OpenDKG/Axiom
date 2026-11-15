// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Enforcement;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class ProcessSpawnAuditHandlerTests
{
    private static readonly DateTimeOffset At = new(2026, 11, 15, 10, 0, 0, TimeSpan.Zero);

    private static ProcessSpawnEvent Spawn(int pid, string image, string parent = @"C:\Users\lab\opencode.exe") =>
        new(pid, 10, image, parent, At);

    private sealed class RecordingSink : IProcessSpawnAuditSink
    {
        public List<ProcessSpawnAudit> Rows { get; } = [];

        public void Record(ProcessSpawnAudit audit) => Rows.Add(audit);
    }

    [Fact]
    public void A_blocked_staged_executable_reaches_the_sink()
    {
        var sink = new RecordingSink();
        var handler = new ProcessSpawnAuditHandler(new AgentProcessSpawnMonitor(), sink);

        var recorded = handler.OnProcessStarted(Spawn(1, @"C:\Users\lab\Downloads\dropper.exe"));

        Assert.True(recorded);
        Assert.Single(sink.Rows);
        Assert.Equal(ProcessSpawnVerdict.Block, sink.Rows[0].Decision.Verdict);
        Assert.Equal(1, handler.Recorded);
    }

    [Fact]
    public void An_allowed_child_does_not_reach_the_sink()
    {
        var sink = new RecordingSink();
        var handler = new ProcessSpawnAuditHandler(new AgentProcessSpawnMonitor(), sink);

        var recorded = handler.OnProcessStarted(
            Spawn(2, @"C:\Windows\System32\notepad.exe", @"C:\Windows\System32\svchost.exe"));

        Assert.False(recorded);
        Assert.Empty(sink.Rows);
    }

    [Fact]
    public void Duplicate_observations_are_forwarded_once()
    {
        var sink = new RecordingSink();
        var handler = new ProcessSpawnAuditHandler(new AgentProcessSpawnMonitor(), sink);
        var spawn = Spawn(3, @"C:\Users\lab\Downloads\dropper.exe");

        Assert.True(handler.OnProcessStarted(spawn));
        Assert.False(handler.OnProcessStarted(spawn));
        Assert.Single(sink.Rows);
        Assert.Equal(1, handler.Recorded);
    }

    [Fact]
    public void Allowlisted_images_do_not_reach_the_sink()
    {
        var sink = new RecordingSink();
        var handler = new ProcessSpawnAuditHandler(new AgentProcessSpawnMonitor(), sink);

        var recorded = handler.OnProcessStarted(
            Spawn(4, @"C:\Users\lab\Downloads\tool.exe"),
            [@"C:\Users\lab\Downloads\tool.exe"]);

        Assert.False(recorded);
        Assert.Empty(sink.Rows);
    }
}
