// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using Axiom.Infrastructure.Windows.Firewall;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

public sealed class FirewallComBoundsTests
{
    [Fact]
    public async Task A_com_call_that_never_returns_times_out_and_queued_calls_are_not_run_later()
    {
        using var executor = new StaComExecutor(TimeSpan.FromMilliseconds(300));
        using var release = new ManualResetEventSlim();
        var queuedRan = false;
        try
        {
            var hung = executor.InvokeAsync(() => { release.Wait(); return 1; }, CancellationToken.None);
            var queued = executor.InvokeAsync(() => queuedRan = true, CancellationToken.None);

            var first = await Assert.ThrowsAsync<TimeoutException>(() => hung.WaitAsync(TimeSpan.FromSeconds(10)));
            var second = await Assert.ThrowsAsync<TimeoutException>(() => queued.WaitAsync(TimeSpan.FromSeconds(10)));

            Assert.Contains("may still complete", first.Message, StringComparison.Ordinal);
            Assert.Contains("was not run", second.Message, StringComparison.Ordinal);
        }
        finally
        {
            release.Set();
        }

        Assert.Equal(7, await executor.InvokeAsync(() => 7, CancellationToken.None));
        Assert.False(queuedRan, "a call reported as not run must never run afterwards");
    }

    [Fact]
    public async Task Executor_can_be_created_lazily_as_the_firewall_adapter_does()
    {
        // Lazy<T> needs a real parameterless constructor; optional parameters do not count.
        using var executor = new Lazy<StaComExecutor>().Value;

        Assert.Equal(1, await executor.InvokeAsync(() => 1, CancellationToken.None));
    }

    [Fact]
    public void Rule_lookup_asks_for_the_rule_by_name_without_enumerating()
    {
        var rules = new FakeRules(new FakeRule("Axiom::a::OUT"));
        var policy = new FakePolicy(rules);

        Assert.Same(rules.Stored, WindowsFirewallPolicyAdapter.FindRule(policy, "Axiom::a::OUT"));
        Assert.Null(WindowsFirewallPolicyAdapter.FindRule(policy, "Axiom::missing::OUT"));
        Assert.Null(WindowsFirewallPolicyAdapter.FindRule(policy, "axiom::a::out")); // names match exactly
    }

    [Fact]
    public void Rule_lookup_does_not_report_other_com_errors_as_a_missing_rule()
    {
        var rules = new FakeRules(new FakeRule("Axiom::a::OUT"))
        {
            Failure = Marshal.GetExceptionForHR(unchecked((int)0x800706BA)), // RPC server unavailable
        };

        Assert.Throws<COMException>(() => WindowsFirewallPolicyAdapter.FindRule(new FakePolicy(rules), "Axiom::a::OUT"));
    }

    public sealed record FakeRule(string Name);

    public sealed class FakePolicy(FakeRules rules)
    {
        public FakeRules Rules { get; } = rules;
    }

    // Deliberately not enumerable: a lookup that walks the rule list fails against this.
    public sealed class FakeRules(FakeRule stored)
    {
        public FakeRule Stored { get; } = stored;

        public Exception? Failure { get; init; }

        // Like INetFwRules.Item: case-insensitive, and "file not found" when there is no such rule.
        public object Item(string name) =>
            Failure is not null ? throw Failure
            : string.Equals(name, Stored.Name, StringComparison.OrdinalIgnoreCase) ? Stored
            : throw new FileNotFoundException();
    }
}
