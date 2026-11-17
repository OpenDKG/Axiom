// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Media;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Protection;
using Axiom.Presentation;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// Off Windows the header lamp, Home and Mini follow the daemon: unknown (neutral) until it answers
/// and again as soon as it stops answering, amber while the shield is on but the network filter has
/// not verified the rules, never a stale green.
/// </summary>
public sealed class ProtectionLampTests
{
    [Fact]
    public async Task Lamp_is_neutral_without_an_answer_amber_unverified_and_never_stale_green()
    {
        if (OperatingSystem.IsWindows())
        {
            return; // Windows keeps its existing header behaviour.
        }

        var client = new MutableProtectionClient { Enabled = true };
        var shell = new ShellViewModel(
            new EmptySource(),
            new NoopTimerFactory(),
            serviceClient: client,
            uiModeService: new FixedUiModeService(UiMode.Simple));
        try
        {
            Assert.False(shell.Firewall.ProtectionKnown);
            Assert.Equal("Shield: unknown", shell.MiniHome.ShieldButtonText);
            Assert.Equal("STATUS UNKNOWN", shell.SimpleHome.HeroBadgeText);

            await shell.ProbeProtectionAsync(force: true);

            Assert.True(shell.Firewall.ProtectionKnown);
            Assert.Equal("SHIELD ON", shell.StatusFirewallBadgeText);
            Assert.Contains("blocks not verified", shell.StatusFirewallText, StringComparison.Ordinal);
            Assert.Equal(Color.Parse(ShellViewModel.UnverifiedLampColor), ((ISolidColorBrush)shell.StatusFirewallBadgeBrush).Color);
            Assert.Equal("Shield: ON", shell.MiniHome.ShieldButtonText);
            Assert.Equal("SHIELD ACTIVE", shell.SimpleHome.HeroBadgeText);

            client.Failure = new ServiceUnavailableException(IpcErrorCodes.ServiceUnavailable, "service offline");
            await shell.ProbeProtectionAsync(force: true);

            Assert.False(shell.Firewall.ProtectionKnown);
            Assert.Equal("UNKNOWN", shell.StatusFirewallBadgeText);
            Assert.Contains("unknown", shell.StatusFirewallText, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(Color.Parse(ShellViewModel.UnknownLampColor), ((ISolidColorBrush)shell.StatusFirewallBadgeBrush).Color);
            Assert.Equal("Shield: unknown", shell.MiniHome.ShieldButtonText);
            Assert.False(shell.SimpleHome.IsShieldActive);
            Assert.Equal("STATUS UNKNOWN", shell.SimpleHome.HeroBadgeText);

            client.Failure = null;
            client.Enabled = false;
            await shell.ProbeProtectionAsync(force: true);
            Assert.True(shell.Firewall.ProtectionKnown);
            Assert.Equal("Shield: OFF", shell.MiniHome.ShieldButtonText);
            Assert.Equal("Protection: off", shell.StatusFirewallText);
        }
        finally
        {
            shell.Dispose();
        }
    }

    private sealed class MutableProtectionClient : IServiceRequestClient
    {
        public bool Enabled { get; set; }

        public Exception? Failure { get; set; }

        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            if (Failure is not null)
            {
                return Task.FromException<T>(Failure);
            }

            if (command != IpcCommandTypes.ProtectionStatus)
            {
                return Task.FromException<T>(new ServiceUnavailableException(IpcErrorCodes.NotSupported, "not supported"));
            }

            object result = new ProtectionStatus
            {
                Enabled = Enabled,
                ServiceElevated = true,
                WriteGateOpen = Enabled,
                AccountName = "root",
                DefaultPolicy = "ask",
                Pending = [],
                Decisions = [],
                AgentPaths = [],
                OwnedRuleCount = 0,
            };
            return Task.FromResult((T)result);
        }
    }

    private sealed class EmptySource : IConnectionSnapshotSource
    {
        public string Name => "test";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UtcNow,
                Connections = [],
                ProcessCount = 0,
                SourceName = "test",
            });
    }

    private sealed class NoopTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new NoopTimer(interval);

        private sealed class NoopTimer(TimeSpan interval) : IUiTimer
        {
            public TimeSpan Interval { get; set; } = interval;

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
