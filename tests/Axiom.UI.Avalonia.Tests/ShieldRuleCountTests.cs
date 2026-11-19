// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Protection;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// The rule count shown with the shield (status bar, Network Control heading) follows the
/// daemon's rules.query answer off Windows, not the stored count in protection.status, which can
/// still hold a rule the filter no longer lists. While that answer is unknown no count is shown.
/// Windows keeps the protection.status count.
/// </summary>
public sealed class ShieldRuleCountTests
{
    [Fact]
    public async Task Status_bar_rule_count_follows_the_daemon_rules_query()
    {
        var client = new DaemonClient { StoredRuleCount = 1 };
        var shell = new ShellViewModel(
            new ServiceSnapshotSource(client),
            new NoopTimerFactory(),
            serviceProbe: new ServiceStatusProbe(client),
            serviceClient: client,
            uiModeService: new FixedUiModeService(UiMode.Advanced));
        try
        {
            await shell.ProbeProtectionAsync(force: true);
            if (OperatingSystem.IsWindows())
            {
                Assert.Contains("1 rule(s)", shell.StatusFirewallText, StringComparison.Ordinal);
                return;
            }

            // rules.query lists no rule although the stored count still says 1.
            Assert.Equal("0", shell.Firewall.OwnedRuleCountText);
            Assert.DoesNotContain("1 rule(s)", shell.StatusFirewallText, StringComparison.Ordinal);
            Assert.Contains("0 rule(s)", shell.StatusFirewallText, StringComparison.Ordinal);
            Assert.DoesNotContain("1 Axiom rule(s)", shell.Firewall.ShieldStatusText, StringComparison.Ordinal);
            Assert.Contains("0 Axiom rule(s)", shell.Firewall.ShieldStatusText, StringComparison.Ordinal);
        }
        finally
        {
            shell.Dispose();
        }
    }

    [Fact]
    public void No_rule_count_is_claimed_before_the_daemon_listed_the_rules()
    {
        using var page = new FirewallPageViewModel(null, new NullUserInteraction());
        Assert.Null(page.QueriedRuleCount);
        Assert.Equal(OperatingSystem.IsWindows() ? 3 : null, page.ShieldRuleCount(3));
    }

    private sealed class DaemonClient : IServiceRequestClient
    {
        public Exception? Failure { get; set; }

        public int StoredRuleCount { get; set; }

        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            if (Failure is not null)
            {
                return Task.FromException<T>(Failure);
            }

            object result = command switch
            {
                IpcCommandTypes.ProtectionStatus => new ProtectionStatus
                {
                    Enabled = true,
                    ServiceElevated = true,
                    WriteGateOpen = true,
                    AccountName = "root",
                    DefaultPolicy = "ask",
                    Pending = [],
                    Decisions = [],
                    AgentPaths = [],
                    OwnedRuleCount = StoredRuleCount,
                },
                IpcCommandTypes.RulesQuery => new FirewallRulesSnapshot
                {
                    Capability = new FirewallCapabilityReport
                    {
                        Status = FirewallCapabilityStatus.Available,
                        ManagedRulesReadable = true,
                        ManagedRuleCount = 0,
                        FilterEnforcement = new FilterEnforcementReport
                        {
                            State = FilterEnforcementState.Verified,
                            Connected = true,
                            PublishedGeneration = 7,
                            Generation = 7,
                            AckedGeneration = 7,
                            LastAckUtc = DateTimeOffset.UtcNow,
                        },
                    },
                    Rules = [],
                    WritesEnabled = true,
                },
                _ => throw new ServiceUnavailableException(IpcErrorCodes.NotSupported, "not supported"),
            };

            return Task.FromResult((T)result);
        }
    }

    private sealed class NoopTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new NoopTimer();

        private sealed class NoopTimer : IUiTimer
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
