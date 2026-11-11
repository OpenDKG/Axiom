// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Service;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class NetworkWatchdogTests
{
    [Theory]
    [InlineData(true, true, true, false)]
    [InlineData(true, true, true, true)]
    [InlineData(true, true, false, false)]
    [InlineData(false, true, true, false)]
    public void A_running_resolver_is_intentional_and_is_never_rolled_back(
        bool enabled,
        bool running,
        bool loopback,
        bool attempted)
    {
        Assert.Equal(
            NetworkWatchdogAction.None,
            NetworkWatchdog.Decide(enabled, running, loopback, attempted));
    }

    [Fact]
    public void A_stopped_resolver_with_loopback_dns_is_restarted_before_dns_is_rolled_back()
    {
        Assert.Equal(
            NetworkWatchdogAction.RestartResolver,
            NetworkWatchdog.Decide(true, false, true, resolverRestartAttempted: false));
        Assert.Equal(
            NetworkWatchdogAction.RestoreDns,
            NetworkWatchdog.Decide(true, false, true, resolverRestartAttempted: true));
    }

    [Fact]
    public void A_failed_disable_repairs_loopback_dns_without_touching_protection()
    {
        Assert.Equal(
            NetworkWatchdogAction.RestoreDns,
            NetworkWatchdog.Decide(false, false, true, resolverRestartAttempted: true));
    }

    [Fact]
    public void No_action_when_the_adapters_do_not_use_loopback_dns()
    {
        Assert.Equal(
            NetworkWatchdogAction.None,
            NetworkWatchdog.Decide(true, false, false, resolverRestartAttempted: false));
    }
}
