// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Enforcement;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class AgentProcessSpawnMonitorTests
{
    private static readonly DateTimeOffset At = new(2026, 11, 15, 9, 0, 0, TimeSpan.Zero);

    private static ProcessSpawnEvent Spawn(int pid, string image, string parent = @"C:\Users\lab\opencode.exe") =>
        new(pid, 10, image, parent, At);

    [Fact]
    public void Allowed_children_are_not_recorded()
    {
        var monitor = new AgentProcessSpawnMonitor();

        var audit = monitor.Observe(Spawn(1, @"C:\Windows\System32\notepad.exe", @"C:\Windows\System32\svchost.exe"));

        Assert.Null(audit);
        Assert.Equal(0, monitor.Count);
    }

    [Fact]
    public void A_staged_executable_from_an_agent_is_recorded_as_block()
    {
        var monitor = new AgentProcessSpawnMonitor();

        var audit = monitor.Observe(Spawn(2, @"C:\Users\lab\Downloads\dropper.exe"));

        Assert.NotNull(audit);
        Assert.Equal(ProcessSpawnVerdict.Block, audit!.Decision.Verdict);
    }

    [Fact]
    public void An_agent_child_is_recorded_once()
    {
        var monitor = new AgentProcessSpawnMonitor();
        var spawn = Spawn(3, @"C:\Windows\System32\notepad.exe");

        Assert.NotNull(monitor.Observe(spawn));
        Assert.Null(monitor.Observe(spawn));
        Assert.Equal(1, monitor.Count);
    }

    [Fact]
    public void Allowlisted_images_are_not_recorded()
    {
        var monitor = new AgentProcessSpawnMonitor();

        var audit = monitor.Observe(
            Spawn(4, @"C:\Users\lab\Downloads\tool.exe"),
            [@"C:\Users\lab\Downloads\tool.exe"]);

        Assert.Null(audit);
    }

    [Fact]
    public void The_remembered_set_is_capped_and_evicts_oldest()
    {
        var monitor = new AgentProcessSpawnMonitor(capacity: 2);

        Assert.NotNull(monitor.Observe(Spawn(5, @"C:\Users\lab\Downloads\a.exe")));
        Assert.NotNull(monitor.Observe(Spawn(6, @"C:\Users\lab\Downloads\b.exe")));
        Assert.NotNull(monitor.Observe(Spawn(7, @"C:\Users\lab\Downloads\c.exe")));
        Assert.Equal(2, monitor.Count);

        // The oldest key was evicted, so it can be recorded again.
        Assert.NotNull(monitor.Observe(Spawn(5, @"C:\Users\lab\Downloads\a.exe")));
    }

    [Fact]
    public void A_different_process_id_is_a_different_observation()
    {
        var monitor = new AgentProcessSpawnMonitor();

        Assert.NotNull(monitor.Observe(Spawn(8, @"C:\Windows\System32\notepad.exe")));
        Assert.NotNull(monitor.Observe(Spawn(9, @"C:\Windows\System32\notepad.exe")));
        Assert.Equal(2, monitor.Count);
    }
}
