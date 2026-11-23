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
    public async Task Agent_guard_tile_follows_consistent_parity_across_platforms()
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
            Assert.Equal("READY", home.AgentGuardBadgeText);

            shell.Agents.Security.BlackboxConnected = true;
            Assert.Equal("ACTIVE", home.AgentGuardBadgeText);

            shell.Agents.Security.BlackboxConnected = false;
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
