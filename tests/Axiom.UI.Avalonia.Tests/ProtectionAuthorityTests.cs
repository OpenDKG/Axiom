// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Media;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Protection;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// The Simple home page and the global header both follow the service protection authority even
/// when another page is selected. A failed probe is unknown: never stale "protected", never "off".
/// </summary>
public sealed class ProtectionAuthorityTests
{
    [Fact]
    public async Task Home_and_header_follow_enable_disable_and_failure_while_overview_is_inactive()
    {
        var client = new MutableProtectionClient { Enabled = true, WriteGateOpen = true };
        var shell = new ShellViewModel(
            new ServiceSnapshotSource(client),
            new NoopTimerFactory(),
            serviceProbe: new ServiceStatusProbe(client),
            serviceClient: client,
            uiModeService: new FixedUiModeService(UiMode.Simple));
        // The fake service reports no filter enforcement: off Windows a shield that is on but not
        // proven by the filter is Degraded (amber, NOT VERIFIED), never the verified green.
        var shieldOnBadge = OperatingSystem.IsWindows() ? "SHIELD ACTIVE" : "NOT VERIFIED";
        var shieldOnLamp = OperatingSystem.IsWindows() ? ShieldProtection.ProtectedColor : ShieldProtection.DegradedColor;
        try
        {
            Assert.Same(shell.SimpleHome, shell.SelectedPage);
            Assert.False(shell.Firewall.ProtectionKnown);

            await shell.ProbeProtectionAsync(force: true);

            Assert.True(shell.Firewall.ProtectionKnown);
            Assert.True(shell.SimpleHome.IsShieldActive);
            Assert.Equal(shieldOnBadge, shell.SimpleHome.HeroBadgeText);
            Assert.Contains("Protection active", shell.Overview.StatusText, StringComparison.Ordinal);
            Assert.Contains("Axiom rules", shell.Overview.StatusText, StringComparison.Ordinal);

            // Another client disables protection while Home is selected: the cache must be fed and
            // Home must stop claiming protection without visiting the Firewall page.
            client.Enabled = false;
            client.WriteGateOpen = false;
            await shell.ProbeProtectionAsync(force: true);

            Assert.False(shell.SimpleHome.IsShieldActive);
            Assert.False(shell.SimpleHome.IsFullyProtected);
            Assert.Equal("MONITORING ONLY", shell.SimpleHome.HeroBadgeText);
            Assert.Equal("Firewall protection is off", shell.SimpleHome.HeroHeadlineText);
            Assert.Equal("Protection: off", shell.StatusFirewallText);
            Assert.Equal(OverviewPageViewModel.ReadOnlyStatus, shell.Overview.StatusText);

            // Advanced page selected: Overview is inactive, the header still follows the authority.
            client.Enabled = true;
            client.WriteGateOpen = true;
            await shell.ProbeProtectionAsync(force: true);
            shell.SwitchToAdvancedModeCommand.Execute(null);
            shell.SelectedPage = shell.AgentDashboard;
            Assert.Contains("Axiom rules", shell.Overview.StatusText, StringComparison.Ordinal);

            client.Enabled = false;
            client.WriteGateOpen = false;
            await shell.ProbeProtectionAsync(force: true);
            Assert.Equal(OverviewPageViewModel.ReadOnlyStatus, shell.Overview.StatusText);
            Assert.Equal("MONITORING ONLY", shell.SimpleHome.HeroBadgeText);

            // A failed probe is unknown, not "off" and not a stale green claim.
            client.Failure = new ServiceUnavailableException(IpcErrorCodes.ServiceUnavailable, "service offline");
            await shell.ProbeProtectionAsync(force: true);

            Assert.False(shell.Firewall.ProtectionKnown);
            Assert.False(shell.SimpleHome.IsShieldActive);
            Assert.False(shell.SimpleHome.IsFullyProtected);
            Assert.Equal("STATUS UNKNOWN", shell.SimpleHome.HeroBadgeText);
            Assert.Equal("Protection status is unknown", shell.SimpleHome.HeroHeadlineText);
            Assert.Contains("cannot confirm", shell.SimpleHome.HeroSummaryText, StringComparison.Ordinal);
            Assert.Equal("Check Firewall", shell.SimpleHome.ShieldButtonText);
            Assert.Contains("Unknown", shell.SimpleHome.FirewallStatusText, StringComparison.Ordinal);
            Assert.Contains("unknown", shell.Overview.StatusText, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Protection active", shell.Overview.StatusText, StringComparison.Ordinal);
            Assert.DoesNotContain("PROTECTED", shell.SimpleHome.HeroBadgeText, StringComparison.Ordinal);
            Assert.Contains("unknown", shell.StatusFirewallText, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("UNKNOWN", shell.StatusFirewallBadgeText);
            Assert.Equal(Color.Parse(ShellViewModel.UnknownLampColor), ((ISolidColorBrush)shell.StatusFirewallBadgeBrush).Color);
            Assert.Equal("Shield: unknown", shell.MiniHome.ShieldButtonText);

            // Recovery restores the service authority and the green claim together.
            client.Failure = null;
            client.Enabled = true;
            client.WriteGateOpen = false;
            await shell.ProbeProtectionAsync(force: true);

            Assert.True(shell.Firewall.ProtectionKnown);
            Assert.True(shell.SimpleHome.IsShieldActive);
            Assert.Equal(shieldOnBadge, shell.SimpleHome.HeroBadgeText);
            Assert.Contains("Axiom rules", shell.Overview.StatusText, StringComparison.Ordinal);
            Assert.Equal("SHIELD ON", shell.StatusFirewallBadgeText);
            Assert.Equal(Color.Parse(shieldOnLamp), ((ISolidColorBrush)shell.StatusFirewallBadgeBrush).Color);
            Assert.Equal("Shield: ON", shell.MiniHome.ShieldButtonText);

            // Losing the service after a green state must not leave the lamp green.
            client.Failure = new ServiceUnavailableException(IpcErrorCodes.ServiceUnavailable, "service offline");
            await shell.ProbeProtectionAsync(force: true);
            Assert.Equal("UNKNOWN", shell.StatusFirewallBadgeText);
            Assert.Equal(Color.Parse(ShellViewModel.UnknownLampColor), ((ISolidColorBrush)shell.StatusFirewallBadgeBrush).Color);
            Assert.Equal("Shield: unknown", shell.MiniHome.ShieldButtonText);
        }
        finally
        {
            shell.Dispose();
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_generic_or_unavailable_probe_failure_clears_the_stale_claim(bool serviceUnavailable)
    {
        var client = new MutableProtectionClient { Enabled = true, WriteGateOpen = true };
        var shell = new ShellViewModel(
            new ServiceSnapshotSource(client),
            new NoopTimerFactory(),
            serviceClient: client,
            uiModeService: new FixedUiModeService(UiMode.Simple));
        try
        {
            await shell.ProbeProtectionAsync(force: true);
            Assert.True(shell.SimpleHome.IsShieldActive);

            client.Failure = serviceUnavailable
                ? new ServiceUnavailableException(IpcErrorCodes.ServiceUnavailable, "service offline")
                : new InvalidOperationException("unexpected IPC fault");
            await shell.ProbeProtectionAsync(force: true);

            Assert.False(shell.Firewall.ProtectionKnown);
            Assert.False(shell.SimpleHome.IsShieldActive);
            Assert.Equal("STATUS UNKNOWN", shell.SimpleHome.HeroBadgeText);
            Assert.DoesNotContain("Read-only inventory", shell.Overview.StatusText, StringComparison.Ordinal);
        }
        finally
        {
            shell.Dispose();
        }
    }

    [Fact]
    public async Task Shield_lamp_is_green_off_windows_only_when_the_filter_proved_enforcement()
    {
        var client = new MutableProtectionClient { Enabled = true, WriteGateOpen = true };
        var shell = new ShellViewModel(
            new ServiceSnapshotSource(client),
            new NoopTimerFactory(),
            serviceProbe: new ServiceStatusProbe(client),
            serviceClient: client,
            uiModeService: new FixedUiModeService(UiMode.Simple));
        try
        {
            await shell.ProbeProtectionAsync(force: true);
            if (OperatingSystem.IsWindows())
            {
                Assert.Equal(EnforcementLevel.Protected, shell.Firewall.ShieldLevel);
                // Windows Firewall reports no verified result, so the label does not claim one.
                Assert.Equal("Settings on", shell.MiniHome.ShieldLevelText);
                return;
            }

            // Not reported (BPF hand-over pending, filter not connected): Degraded everywhere.
            Assert.Equal(EnforcementLevel.Degraded, shell.Firewall.ShieldLevel);
            Assert.False(shell.SimpleHome.IsFullyProtected);
            Assert.Equal("Degraded", shell.MiniHome.ShieldLevelText);
            Assert.True(shell.MiniHome.IsShieldToneWarn);
            Assert.Contains("blocks not verified", shell.StatusFirewallText, StringComparison.Ordinal);

            // The filter proves enforcement: the same model turns every surface green.
            shell.Firewall.Enforcement = new FilterEnforcementSummary { IsVerified = true, NotVerifiedReason = string.Empty };
            await shell.ProbeProtectionAsync(force: true);
            Assert.Equal(EnforcementLevel.Protected, shell.Firewall.ShieldLevel);
            Assert.Equal("SHIELD ACTIVE", shell.SimpleHome.HeroBadgeText);
            Assert.Equal("Protected", shell.MiniHome.ShieldLevelText);
            Assert.True(shell.MiniHome.IsShieldToneOk);
            Assert.Equal(Color.Parse(ShieldProtection.ProtectedColor), ((ISolidColorBrush)shell.StatusFirewallBadgeBrush).Color);

            // Service lost: unknown (idle tone), not the previous green.
            client.Failure = new ServiceUnavailableException(IpcErrorCodes.ServiceUnavailable, "service offline");
            await shell.ProbeProtectionAsync(force: true);
            Assert.Null(shell.Firewall.ShieldLevel);
            Assert.Equal("Unknown", shell.MiniHome.ShieldLevelText);
            Assert.True(shell.MiniHome.IsShieldToneIdle);
            Assert.False(shell.MiniHome.IsShieldToneOk);
        }
        finally
        {
            shell.Dispose();
        }
    }

    private sealed class MutableProtectionClient : IServiceRequestClient
    {
        private bool _enabled;
        private bool _writeGateOpen;

        public bool Enabled
        {
            get => _enabled;
            set
            {
                _enabled = value;
                if (!value)
                {
                    _writeGateOpen = false;
                }
            }
        }

        public bool WriteGateOpen
        {
            get => _writeGateOpen;
            set => _writeGateOpen = value;
        }

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
                    Enabled = Enabled,
                    ServiceElevated = true,
                    WriteGateOpen = WriteGateOpen,
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
