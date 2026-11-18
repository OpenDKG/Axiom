// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class LocalModuleRuntimeTests
{
    [Fact]
    public void Process_timeout_applies_while_output_streams_are_open()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var messages = new List<string>();
        var elapsed = Stopwatch.StartNew();

        Assert.False(LocalModuleRuntime.RunHiddenPowerShell(
            "Start-Sleep -Seconds 20", messages.Add, TimeSpan.FromMilliseconds(750)));

        Assert.Contains(messages, line => line.EndsWith(" timed out.", StringComparison.Ordinal));
        Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(10), $"Process returned after {elapsed.Elapsed}.");
    }

    [Fact]
    public void Process_drains_standard_error_even_when_standard_output_is_still_open()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var messages = new List<string>();

        Assert.True(LocalModuleRuntime.RunHiddenPowerShell(
            "[Console]::Error.WriteLine(('x' * 131072)); [Console]::Out.WriteLine('stdout')",
            messages.Add,
            TimeSpan.FromSeconds(15)));

        Assert.Contains("stdout", messages);
        Assert.Contains(messages, line => line.Length == 131072);
    }

    [Fact]
    public void Launch_requests_share_the_pending_start_until_it_expires_or_is_stopped()
    {
        var clock = new ManualTimeProvider();
        var gate = new ModuleLaunchGate(TimeSpan.FromSeconds(60), clock);
        var count = 0;
        bool Start()
        {
            count++;
            return true;
        }

        var results = new bool[8];
        Parallel.For(0, results.Length, index => results[index] = gate.Start(() => false, Start));
        Assert.All(results, result => Assert.True(result));
        Assert.Equal(1, count);

        Assert.False(gate.Stop(() => false));
        Assert.True(gate.Start(() => false, Start));
        Assert.Equal(1, count);

        clock.Timestamp += clock.TimestampFrequency * 60;
        Assert.True(gate.Start(() => false, Start));
        Assert.Equal(2, count);

        Assert.True(gate.Stop(() => true));
        Assert.True(gate.Start(() => false, Start));
        Assert.Equal(3, count);
    }

    [Fact]
    public void Launch_gate_rechecks_after_a_failure_and_never_launches_on_an_open_port()
    {
        var gate = new ModuleLaunchGate(TimeSpan.FromSeconds(60));

        Assert.False(gate.Start(() => false, () => false));
        Assert.True(gate.Start(() => false, () => true));
        Assert.True(gate.Start(() => true, () => throw new InvalidOperationException()));
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        public long Timestamp { get; set; }

        public override long GetTimestamp() => Timestamp;
    }
}
