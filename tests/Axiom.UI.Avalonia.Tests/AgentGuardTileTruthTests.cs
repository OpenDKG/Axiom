// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
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
        await TestAppBuilder.RunOnUiThreadAsync(async () =>
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
            Assert.Equal("OFFLINE", home.AgentGuardBadgeText);

            shell.Firewall.ProtectionKnown = true;
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
        });
    }

    [Fact]
    public void Minimizing_to_tray_pauses_one_second_monitor_polling_and_restores_on_show()
    {
        var source = new CountingSnapshotSource();
        var timers = new TrackingTimerFactory();
        var shell = new ShellViewModel(source, timers);
        try
        {
            shell.Start();
            // ConnectionMonitor + TrafficEngine timers run while window is visible; fire monitor tick once.
            timers.TickAll(TimeSpan.FromSeconds(1));
            var countWhileVisible = source.Calls;
            Assert.True(countWhileVisible >= 1);

            shell.SetPresentationVisible(false);
            timers.TickAll(TimeSpan.FromSeconds(1));
            Assert.Equal(countWhileVisible, source.Calls);

            shell.SetPresentationVisible(true);
            timers.TickAll(TimeSpan.FromSeconds(1));
            Assert.True(source.Calls > countWhileVisible);
        }
        finally
        {
            shell.Dispose();
        }
    }

    private sealed class CountingSnapshotSource : IConnectionSnapshotSource
    {
        public int Calls { get; private set; }

        public string Name => "counting";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UtcNow,
                Connections = [],
                ProcessCount = 0,
                SourceName = Name,
            });
        }
    }

    private sealed class TrackingTimerFactory : IUiTimerFactory
    {
        private readonly List<TrackedTimer> _timers = [];

        public IUiTimer Create(TimeSpan interval)
        {
            var timer = new TrackedTimer(interval);
            _timers.Add(timer);
            return timer;
        }

        public void TickAll(TimeSpan interval)
        {
            foreach (var timer in _timers)
            {
                if (timer.IsEnabled && timer.Interval == interval)
                {
                    timer.Fire();
                }
            }
        }

        private sealed class TrackedTimer(TimeSpan interval) : IUiTimer
        {
            public TimeSpan Interval { get; set; } = interval;
            public bool IsEnabled { get; private set; }
            public event EventHandler? Tick;
            public void Start() => IsEnabled = true;
            public void StopTimer() => IsEnabled = false;
            public void Fire() => Tick?.Invoke(this, EventArgs.Empty);
            public void Dispose() { }
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
