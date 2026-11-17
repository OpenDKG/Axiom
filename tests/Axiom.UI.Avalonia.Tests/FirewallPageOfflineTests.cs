// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Protection;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// Network Control must follow the same shield model as the footer lamp: when the daemon stops
/// answering, the page body (shield heading, filter/enforcement lines, any "verified") switches to
/// unknown at once, and it recovers from the daemon's next answer. Off Windows only; Windows keeps
/// its behaviour.
/// </summary>
public sealed class FirewallPageOfflineTests
{
    [Fact]
    public async Task Network_control_body_goes_unknown_when_the_daemon_stops_and_recovers()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var client = new DaemonClient();
        var shell = new ShellViewModel(
            new ServiceSnapshotSource(client),
            new NoopTimerFactory(),
            serviceProbe: new ServiceStatusProbe(client),
            serviceClient: client,
            uiModeService: new FixedUiModeService(UiMode.Advanced));
        try
        {
            var page = shell.Firewall;
            await shell.ProbeProtectionAsync(force: true);
            Assert.Equal("ON", page.ShieldBadgeText);
            Assert.Contains("verified", page.FilterEnforcedText, StringComparison.Ordinal);
            Assert.Contains("verified", page.FilterConnectionText, StringComparison.Ordinal);
            Assert.Equal("Available", page.CapabilityStatusText);
            Assert.Equal(EnforcementLevel.Protected, page.ShieldLevel);

            // Daemon stops: the lamp says UNKNOWN and so must the page body.
            client.Failure = new ServiceUnavailableException(IpcErrorCodes.ServiceUnavailable, "service offline");
            await shell.ProbeProtectionAsync(force: true);
            Assert.Equal("UNKNOWN", shell.StatusFirewallBadgeText);
            Assert.Null(page.ShieldLevel);
            Assert.Equal("UNKNOWN", page.ShieldBadgeText);
            Assert.Contains("unknown", page.ShieldStatusText, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("verified", page.FilterEnforcedText, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("verified", page.FilterConnectionText, StringComparison.OrdinalIgnoreCase);
            Assert.False(page.Enforcement.IsVerified);
            Assert.NotEqual("Available", page.CapabilityStatusText);
            Assert.NotEqual("SHIELD ON", page.NoticeBadgeText);
            Assert.DoesNotContain("Shield is on", page.NoticeText, StringComparison.Ordinal);

            // Daemon back: the shield answer returns at once, but not "verified" before the filter
            // state is read again; the next enforcement re-read restores it.
            client.Failure = null;
            await shell.ProbeProtectionAsync(force: true);
            Assert.Equal("ON", page.ShieldBadgeText);
            Assert.NotEqual(EnforcementLevel.Protected, page.ShieldLevel);
            page.RefreshEnforcementIfStale(DateTimeOffset.UtcNow + FirewallPageViewModel.EnforcementRefreshInterval);
            Assert.Equal("Available", page.CapabilityStatusText);
            Assert.Contains("verified", page.FilterEnforcedText, StringComparison.Ordinal);
            Assert.Equal(EnforcementLevel.Protected, page.ShieldLevel);
        }
        finally
        {
            shell.Dispose();
        }
    }

    private sealed class DaemonClient : IServiceRequestClient
    {
        public Exception? Failure { get; set; }

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
                    OwnedRuleCount = 0,
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
