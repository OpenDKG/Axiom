// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;
using DaemonClient = Axiom.UI.Avalonia.Tests.DaemonStoppedStaleStateTests.DaemonClient;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// Second VM look (v1-look2): every surface must leave the protected state together the moment
/// any service call or the monitor finds the daemon gone, and come back from the same answer,
/// instead of each page waiting for its own poll. Maintainer ruling: unreachable is UNKNOWN,
/// never protected. Off Windows only; Windows keeps its behaviour.
/// </summary>
[Collection(DaemonStoppedStaleStateSerial.Name)]
public sealed class ServiceReachabilitySignalTests
{
    private static ServiceUnavailableException Offline() =>
        new(IpcErrorCodes.ServiceUnavailable, "The service did not respond in time.");

    [Fact]
    public async Task A_failed_call_on_any_page_turns_header_footer_network_control_and_home_unknown_at_once()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await TestAppBuilder.RunOnUiThreadAsync(async () =>
        {
        var client = new DaemonClient();
        var shell = NewShell(client, UiMode.Advanced);
        try
        {
            shell.SelectedPage = shell.Firewall;
            await shell.ProbeProtectionAsync(force: true);
            Assert.Equal("SHIELD ON", shell.StatusFirewallBadgeText);
            Assert.Equal("Disable protection", shell.Firewall.ShieldActionText);

            // The daemon stops; the next read that notices is an unrelated page's refresh (here
            // the agent page's indicator queue), not the shell probe and not Network Control.
            client.Failure = Offline();
            await InvokePrivateAsync(shell.Agents, "RefreshThreatShareAsync");

            AssertAllUnknown(shell);
        }
        finally
        {
            shell.Dispose();
        }
        });
    }

    [Fact]
    public async Task A_monitor_that_loses_the_daemon_turns_every_surface_unknown_without_waiting_for_the_probe()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await TestAppBuilder.RunOnUiThreadAsync(async () =>
        {
        var client = new DaemonClient();
        var shell = NewShell(client, UiMode.Advanced);
        try
        {
            shell.SelectedPage = shell.Firewall;
            await shell.ProbeProtectionAsync(force: true);
            Assert.Equal("SHIELD ON", shell.StatusFirewallBadgeText);

            // lx-40: 6 s after the stop the header said "Monitor unavailable" while the page and
            // the footer still said ON / verified. The probe is throttled; do not run it here.
            client.Failure = Offline();
            await PollMonitorAsync(shell);

            AssertAllUnknown(shell);
            Assert.Contains("Monitor unavailable", shell.Overview.StatusText, StringComparison.Ordinal);
        }
        finally
        {
            shell.Dispose();
        }
        });
    }

    [Fact]
    public async Task A_service_error_answer_is_not_an_unreachable_daemon()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await TestAppBuilder.RunOnUiThreadAsync(async () =>
        {
        var client = new DaemonClient();
        var shell = NewShell(client, UiMode.Advanced);
        try
        {
            shell.SelectedPage = shell.Firewall;
            await shell.ProbeProtectionAsync(force: true);

            // The daemon answered with an error (here: a command this fake does not support).
            await InvokePrivateAsync(shell.Agents, "RefreshThreatShareAsync");

            Assert.Equal("SHIELD ON", shell.StatusFirewallBadgeText);
            Assert.True(shell.Firewall.ProtectionKnown);
        }
        finally
        {
            shell.Dispose();
        }
        });
    }

    [Fact]
    public async Task On_return_the_header_follows_the_same_answer_as_page_and_footer()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await TestAppBuilder.RunOnUiThreadAsync(async () =>
        {
        var client = new DaemonClient();
        var shell = NewShell(client, UiMode.Advanced);
        try
        {
            shell.SelectedPage = shell.Firewall;
            await shell.ProbeProtectionAsync(force: true);
            await InvokePrivateAsync(shell, "ProbeServiceAsync", true);

            client.Failure = Offline();
            await InvokePrivateAsync(shell, "ProbeServiceAsync", true);
            await shell.ProbeProtectionAsync(force: true);
            AssertAllUnknown(shell);

            // lx-15 / m-16: the page's own re-read answers first; the service probe that said
            // "offline" is not due for seconds. Header, footer and page must agree at once.
            client.Failure = null;
            await shell.Firewall.RefreshCommand.ExecuteAsync(null);

            Assert.Equal("Disable protection", shell.Firewall.ShieldActionText);
            Assert.Equal("SHIELD ON", shell.StatusFirewallBadgeText);
            Assert.DoesNotContain("offline", shell.Overview.StatusText, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("unknown", shell.Overview.StatusText, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Protection active", shell.Overview.StatusText, StringComparison.Ordinal);
            Assert.DoesNotContain("offline", shell.StatusIpcText, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            shell.Dispose();
        }
        });
    }

    [Fact]
    public async Task Network_control_opened_while_the_daemon_is_down_never_says_no_rules_exist()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await TestAppBuilder.RunOnUiThreadAsync(async () =>
        {
        var client = new DaemonClient { Failure = Offline() };
        var shell = NewShell(client, UiMode.Advanced);
        try
        {
            // lx-13 / m-14: no successful read in this page yet.
            shell.SelectedPage = shell.Firewall;
            await shell.Firewall.RefreshCommand.ExecuteAsync(null);

            var page = shell.Firewall;
            Assert.Empty(page.Rules);
            Assert.Contains("could not be read", page.StatusText, StringComparison.Ordinal);
            Assert.Equal(FirewallPageViewModel.RulesUnreadableText, page.EmptyRulesText);
            Assert.DoesNotContain("were found", page.EmptyRulesText, StringComparison.Ordinal);
            Assert.Equal("—", page.OwnedRuleCountText);
            Assert.Equal("UNKNOWN", page.ShieldBadgeText);
        }
        finally
        {
            shell.Dispose();
        }
        });
    }

    [Fact]
    public async Task Simple_home_turns_verified_on_the_first_probe_after_the_filter_acknowledges()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await TestAppBuilder.RunOnUiThreadAsync(async () =>
        {
        var client = new DaemonClient { FilterState = FilterEnforcementState.Pending };
        var shell = NewShell(client, UiMode.Simple);
        try
        {
            shell.SelectedPage = shell.SimpleHome;
            await shell.ProbeProtectionAsync(force: true);
            Assert.Equal("NOT VERIFIED", shell.SimpleHome.HeroBadgeText);

            // lx-32 / lx-54: Network Control was verified within 3 s, Simple home still said
            // "has not acknowledged rules generation N" at 10 s. The next probe after the ack
            // must re-read enforcement while it is unverified, not wait for a later interval.
            client.FilterState = FilterEnforcementState.Verified;
            await shell.ProbeProtectionAsync(force: true);
            await WaitUntilAsync(() => shell.Firewall.Enforcement.IsEnforcementVerified);

            Assert.NotEqual("NOT VERIFIED", shell.SimpleHome.HeroBadgeText);
            Assert.DoesNotContain("not verified", shell.StatusFirewallText, StringComparison.Ordinal);
        }
        finally
        {
            shell.Dispose();
        }
        });
    }

    [Fact]
    public async Task Simple_home_button_only_checks_while_the_state_is_unknown()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await TestAppBuilder.RunOnUiThreadAsync(async () =>
        {
        var client = new DaemonClient();
        var shell = NewShell(client, UiMode.Simple);
        try
        {
            shell.SelectedPage = shell.SimpleHome;
            await shell.ProbeProtectionAsync(force: true);
            Assert.Equal("Turn Shield Off", shell.SimpleHome.ShieldButtonText);

            client.Failure = Offline();
            await shell.ProbeProtectionAsync(force: true);
            Assert.Equal("STATUS UNKNOWN", shell.SimpleHome.HeroBadgeText);
            Assert.Equal("Check Firewall", shell.SimpleHome.ShieldButtonText);

            client.Commands.Clear();
            shell.SimpleHome.ToggleShieldCommand.Execute(null);
            Assert.DoesNotContain(IpcCommandTypes.ProtectionDisable, client.Commands);
            Assert.DoesNotContain(IpcCommandTypes.ProtectionEnable, client.Commands);
        }
        finally
        {
            shell.Dispose();
        }
        });
    }

    [Fact]
    public async Task Row_actions_are_disabled_while_the_state_is_unknown()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await TestAppBuilder.RunOnUiThreadAsync(async () =>
        {
        var client = new DaemonClient();
        var shell = NewShell(client, UiMode.Advanced);
        try
        {
            shell.SelectedPage = shell.Firewall;
            var page = shell.Firewall;
            await shell.ProbeProtectionAsync(force: true);
            var row = Assert.Single(page.Rules);
            Assert.True(row.CanUnblock);
            Assert.True(page.UnblockRuleCommand.CanExecute(row));

            var changed = 0;
            page.UnblockRuleCommand.CanExecuteChanged += (_, _) => changed++;
            client.Failure = Offline();
            await shell.ProbeProtectionAsync(force: true);

            row = Assert.Single(page.Rules);
            Assert.True(row.IsLastKnown);
            Assert.True(changed > 0, "the Unblock button was not told to re-evaluate");
            Assert.False(page.UnblockRuleCommand.CanExecute(row));

            // m-31: macOS kept ShieldEnabled from the last answer; unknown must still disable.
            page.ShieldEnabled = true;
            Assert.False(page.ProtectionKnown);
            Assert.False(page.UnblockRuleCommand.CanExecute(row));
            Assert.False(page.ToggleDecisionCommand.CanExecute(null));
        }
        finally
        {
            shell.Dispose();
        }
        });
    }

    private static void AssertAllUnknown(ShellViewModel shell)
    {
        var page = shell.Firewall;
        Assert.False(page.ProtectionKnown);
        Assert.Equal("UNKNOWN", page.ShieldBadgeText);
        Assert.Equal("Check protection", page.ShieldActionText);
        Assert.DoesNotContain("verified", page.FilterConnectionText, StringComparison.OrdinalIgnoreCase);
        Assert.All(page.Rules, row => Assert.True(row.IsLastKnown));

        Assert.Equal("UNKNOWN", shell.StatusFirewallBadgeText);
        Assert.StartsWith("Protection: unknown", shell.StatusFirewallText, StringComparison.Ordinal);
        Assert.Contains("Protection status unknown", shell.Overview.StatusText, StringComparison.Ordinal);
        Assert.DoesNotContain("Protection active", shell.Overview.StatusText, StringComparison.Ordinal);

        Assert.Equal("STATUS UNKNOWN", shell.SimpleHome.HeroBadgeText);
        Assert.Equal("Unknown", shell.MiniHome.ShieldLevelText);
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 50 && !condition(); i++)
        {
            await Task.Delay(10);
        }
    }

    private static Task InvokePrivateAsync(object target, string method, params object[] args) =>
        (Task)target.GetType()
            .GetMethod(method, BindingFlags.NonPublic | BindingFlags.Instance)!
            .Invoke(target, args.Length == 0 ? null : args)!;

    private static Task PollMonitorAsync(ShellViewModel shell)
    {
        var monitor = (ConnectionMonitor)typeof(ShellViewModel)
            .GetField("_monitor", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(shell)!;
        return monitor.PollAsync();
    }

    private static ShellViewModel NewShell(DaemonClient client, UiMode mode) => new(
        new ServiceSnapshotSource(client),
        new NoTimers(),
        serviceProbe: new ServiceStatusProbe(client),
        serviceClient: client,
        uiModeService: new FixedUiModeService(mode));

    private sealed class NoTimers : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new Timer { Interval = interval };

        private sealed class Timer : IUiTimer
        {
            public TimeSpan Interval { get; set; }

            public bool IsEnabled { get; private set; }

            public event EventHandler? Tick
            {
                add { }
                remove { }
            }

            public void Start() => IsEnabled = true;

            public void StopTimer() => IsEnabled = false;

            public void Dispose()
            {
            }
        }
    }
}
