// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Privacy;
using Axiom.Contracts.Protection;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// A daemon that stops answering must not leave Privacy Shield presented as filtering: the saved
/// toggle may still be on, but the resolver state is unknown and every home surface says so.
/// </summary>
public sealed class PrivacyShieldAvailabilityTests
{
    [Fact]
    public async Task Stopped_daemon_makes_privacy_unknown_on_home_and_recovers_on_retry()
    {
        var client = new PrivacyClient();
        var shell = new ShellViewModel(
            new ServiceSnapshotSource(client),
            new NoopTimerFactory(),
            serviceClient: client,
            uiModeService: new FixedUiModeService(UiMode.Simple));
        try
        {
            var page = shell.PrivacyShield;
            await page.RefreshCommand.ExecuteAsync(null);

            Assert.False(page.IsServiceUnavailable);
            Assert.True(page.IsResolverActive);
            Assert.Contains("Blocking", shell.SimpleHome.PrivacyStatusText, StringComparison.Ordinal);
            Assert.Equal("Turn Off", shell.SimpleHome.PrivacyActionText);
            Assert.Equal("Privacy: ON", shell.MiniHome.PrivacyButtonText);

            client.Failure = new ServiceUnavailableException(IpcErrorCodes.ServiceUnavailable, "service offline");
            await page.RefreshCommand.ExecuteAsync(null);

            // Unknown: the last-known running state is not kept.
            Assert.True(page.IsServiceUnavailable);
            Assert.False(page.IsResolverActive);
            Assert.Equal("Unknown — the local service did not answer", shell.SimpleHome.PrivacyStatusText);
            Assert.Equal("Retry", shell.SimpleHome.PrivacyActionText);
            Assert.False(shell.SimpleHome.IsFullyProtected);
            Assert.Equal("Privacy: unknown", shell.MiniHome.PrivacyButtonText);
            Assert.DoesNotContain("PROTECTED", shell.SimpleHome.HeroBadgeText, StringComparison.Ordinal);

            // Retry re-reads; it never sends a guessed enable/disable request while unknown.
            client.Failure = null;
            client.Commands.Clear();
            await page.RefreshCommand.ExecuteAsync(null);

            Assert.False(page.IsServiceUnavailable);
            Assert.True(page.IsResolverActive);
            Assert.Contains("Blocking", shell.SimpleHome.PrivacyStatusText, StringComparison.Ordinal);
            Assert.Equal("Privacy: ON", shell.MiniHome.PrivacyButtonText);
            Assert.DoesNotContain(IpcCommandTypes.PrivacyConfigure, client.Commands);
        }
        finally
        {
            shell.Dispose();
        }
    }

    private sealed class PrivacyClient : IServiceRequestClient
    {
        public Exception? Failure { get; set; }

        public List<string> Commands { get; } = [];

        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            Commands.Add(command);
            if (Failure is not null)
            {
                return Task.FromException<T>(Failure);
            }

            object result = command switch
            {
                IpcCommandTypes.PrivacyStatus => new PrivacyShieldStatus
                {
                    State = "Active",
                    Enabled = true,
                    Running = true,
                    Port = 53,
                    BindAddress = "127.0.0.1",
                    Upstream = "1.1.1.1:53",
                    Queries = 10,
                    Allowed = 7,
                    Blocked = 3,
                    Errors = 0,
                    RuleCount = 120,
                    Settings = new PrivacyShieldSettings { Enabled = true, Port = 53 },
                },
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
                IpcCommandTypes.Snapshot => new ConnectionSnapshot
                {
                    CapturedUtc = DateTimeOffset.UtcNow,
                    Connections = [],
                    ProcessCount = 0,
                    SourceName = "fake axiomd",
                },
                IpcCommandTypes.ServiceHealth => new ServiceHealth
                {
                    Status = "ok",
                    UptimeSeconds = 1,
                    SourceName = "fake axiomd",
                    PollIntervalSeconds = 1,
                    ConnectionCount = 0,
                    ProcessCount = 0,
                },
                IpcCommandTypes.Capabilities => new ServiceCapabilities
                {
                    ProtocolVersion = 1,
                    Commands = [],
                    Monitoring = true,
                    FirewallWrites = false,
                    Milestone = "test",
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
