// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Protection;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// The Simple home "AI AGENT GUARD" tile. Off Windows no Blackbox host hook is proven yet
/// (decision 441-v2): the tile says not verified / unsupported whatever the daemon or the
/// firewall reports, and only a verified host or OS deny may read ACTIVE. Windows keeps its
/// existing READY / DETECTED / ACTIVE wording.
/// </summary>
public sealed class AgentGuardTileTruthTests
{
    [Fact]
    public async Task Agent_guard_tile_is_not_verified_off_windows_whatever_the_firewall_says()
    {
        var client = new ProtectionClient();
        var shell = new ShellViewModel(
            new ServiceSnapshotSource(client),
            new NoopTimerFactory(),
            serviceProbe: new ServiceStatusProbe(client),
            serviceClient: client,
            uiModeService: new FixedUiModeService(UiMode.Simple));
        try
        {
            var home = shell.SimpleHome;
            if (OperatingSystem.IsWindows())
            {
                // Windows: upstream wording unchanged.
                Assert.Equal("READY", home.AgentGuardBadgeText);
                return;
            }

            // Daemon stopped: never READY.
            client.Failure = new ServiceUnavailableException(IpcErrorCodes.ServiceUnavailable, "service offline");
            await shell.ProbeProtectionAsync(force: true);
            AssertNotVerified(home);

            // Daemon up, shield on and the firewall filter verified: still not agent protection.
            client.Failure = null;
            await shell.ProbeProtectionAsync(force: true);
            shell.Firewall.Enforcement = new FilterEnforcementSummary { IsVerified = true, NotVerifiedReason = string.Empty };
            Assert.Equal(EnforcementLevel.Protected, shell.Firewall.ShieldLevel);
            AssertNotVerified(home);

            // A Blackbox guard that reports connected is shown, but blocking stays not verified.
            shell.Agents.Security.BlackboxConnected = true;
            Assert.Equal("NOT VERIFIED", home.AgentGuardBadgeText);
            Assert.Contains("connected", home.AgentGuardStatusText, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("not verified", home.AgentGuardStatusText, StringComparison.Ordinal);

            // Only a verified host/OS deny from the enforcement controller may read ACTIVE.
            shell.Agents.Enforcement = EnforcementSurfaceState.Current with
            {
                Verification = EnforcementVerification.HostDenyVerified,
                VerificationLabel = "HOST DENY VERIFIED",
            };
            Assert.Equal("ACTIVE", home.AgentGuardBadgeText);
        }
        finally
        {
            shell.Dispose();
        }
    }

    private static void AssertNotVerified(SimpleHomePageViewModel home)
    {
        Assert.Equal("NOT VERIFIED", home.AgentGuardBadgeText);
        Assert.NotEqual("READY", home.AgentGuardBadgeText);
        Assert.Contains("not verified", home.AgentGuardStatusText, StringComparison.Ordinal);
        Assert.Contains(PlatformText.OsName, home.AgentGuardStatusText, StringComparison.Ordinal);
        Assert.DoesNotContain("blocks risky", home.AgentGuardStatusText, StringComparison.Ordinal);
    }

    private sealed class ProtectionClient : IServiceRequestClient
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
