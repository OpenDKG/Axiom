// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Enforcement;
using Axiom.Service;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class ProcessSpawnAuditRuntimeTests
{
    private static readonly DateTimeOffset At = new(2026, 11, 15, 12, 30, 0, TimeSpan.Zero);

    private sealed class FakeSource : IProcessStartSource
    {
        public event EventHandler<ProcessSpawnEvent>? ProcessStarted;

        public int Starts { get; private set; }

        public int Subscribers => ProcessStarted?.GetInvocationList().Length ?? 0;

        public bool Disposed { get; private set; }

        public void Start() => Starts++;

        public void Raise(ProcessSpawnEvent spawn) => ProcessStarted?.Invoke(this, spawn);

        public void Dispose() => Disposed = true;
    }

    private sealed class RecordingSink : IProcessSpawnAuditSink
    {
        public List<ProcessSpawnAudit> Rows { get; } = [];

        public void Record(ProcessSpawnAudit audit) => Rows.Add(audit);
    }

    private static (ProcessSpawnAuditRuntime runtime, FakeSource source, RecordingSink sink) Create()
    {
        var sink = new RecordingSink();
        var handler = new ProcessSpawnAuditHandler(new AgentProcessSpawnMonitor(), sink);
        var source = new FakeSource();
        return (new ProcessSpawnAuditRuntime(source, handler), source, sink);
    }

    private static ProcessSpawnEvent Spawn(int pid, string image) =>
        new(pid, 10, image, @"C:\Users\lab\opencode.exe", At);

    [Fact]
    public void A_blocked_spawn_reaches_the_sink_after_start()
    {
        var (runtime, source, sink) = Create();
        runtime.Start();

        source.Raise(Spawn(1, @"C:\Users\lab\Downloads\dropper.exe"));

        Assert.Single(sink.Rows);
        Assert.Equal(ProcessSpawnVerdict.Block, sink.Rows[0].Decision.Verdict);
        Assert.Equal(1, runtime.Recorded);
        Assert.Equal(1, source.Starts);
    }

    [Fact]
    public void Starting_twice_does_not_double_subscribe()
    {
        var (runtime, source, sink) = Create();
        runtime.Start();
        runtime.Start();

        source.Raise(Spawn(2, @"C:\Windows\System32\notepad.exe"));

        Assert.Single(sink.Rows);
        Assert.Equal(1, source.Starts);
    }

    [Fact]
    public void Dispose_detaches_the_subscription_and_disposes_the_source()
    {
        var (runtime, source, sink) = Create();
        runtime.Start();
        runtime.Dispose();

        source.Raise(Spawn(3, @"C:\Users\lab\Downloads\dropper.exe"));

        Assert.Empty(sink.Rows);
        Assert.Equal(0, source.Subscribers);
        Assert.True(source.Disposed);
    }
}
