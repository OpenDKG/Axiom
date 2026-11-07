// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Protection;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class AvaloniaPageTests
{
    [Fact]
    public void Shell_exposes_all_eleven_parity_pages()
    {
        var shell = new ShellViewModel(new FakeSource(), new FakeTimerFactory());

        Assert.Equal(12, shell.Pages.Count);
        Assert.Contains(shell.Pages, page => page.Title == "Security");
        Assert.Contains(shell.Pages, page => page.Title == "Agents");
        Assert.Contains(shell.Pages, page => page.Title == "Agent Stats");
        Assert.False(shell.IsServiceMode);

        shell.Dispose();
    }

    [Fact]
    public void Events_page_requires_the_service_instead_of_generating_rows()
    {
        var page = new EventsPageViewModel(null, new FakeTimerFactory(), new NullUserInteraction());

        Assert.True(page.IsEmpty);
        Assert.Contains("local service", page.StatusText, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(page.Rows);

        page.Dispose();
    }

    [Fact]
    public void Privacy_shield_reports_service_required_without_changing_dns()
    {
        var page = new PrivacyShieldPageViewModel(
            null,
            new NullUserInteraction(),
            new UnsupportedDnsAdapterHelper(),
            new FakeTimerFactory());

        Assert.False(page.IsSupported);
        Assert.Equal("SERVICE REQUIRED", page.StatusBadge);
        Assert.Contains("No DNS settings were changed", page.DetailText);

        page.Dispose();
    }

    [Fact]
    public async Task Firewall_page_reports_an_offline_service()
    {
        var page = new FirewallPageViewModel(new OfflineClient(), new NullUserInteraction());

        await Task.Delay(200);

        Assert.Equal("Service offline", page.CapabilityStatusText);
        Assert.True(page.IsEmpty);
        Assert.False(page.WritesEnabled);
        Assert.Empty(page.Rules);
    }

    private sealed class FakeSource : IConnectionSnapshotSource
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

    [Fact]
    public async Task Firewall_page_applies_shield_status()
    {
        var pending = new ProtectionPendingApp
        {
            AppPath = @"C:\Tools\opencode.exe",
            AppName = "opencode.exe",
            SocketCount = 3,
            FirstObservedUtc = DateTimeOffset.UnixEpoch,
            IsAgent = true,
        };

        var status = new ProtectionStatus
        {
            Enabled = true,
            ServiceElevated = true,
            WriteGateOpen = true,
            AccountName = "SYSTEM",
            DefaultPolicy = "ask",
            Pending = [pending],
            Decisions = [],
            AgentPaths = [@"C:\Tools\opencode.exe"],
            AgentLockdown = false,
            OwnedRuleCount = 1,
        };

        var page = new FirewallPageViewModel(new ShieldClient(status), new NullUserInteraction());

        await Task.Delay(300);

        Assert.True(page.ShieldEnabled);
        Assert.True(page.ServiceElevated);
        Assert.True(page.WritesEnabled);
        Assert.Equal("ON", page.ShieldBadgeText);
        Assert.Equal(1, page.PendingCount);
        Assert.True(page.HasPending);
        Assert.Equal(1, page.AgentPathCount);
        Assert.Single(page.Pending);
        Assert.Equal("opencode.exe", page.Pending[0].AppName);
        Assert.True(page.Pending[0].IsAgent);
    }

    [Theory]
    [InlineData("PROTECTED", true, false, false)]
    [InlineData("VERIFIED BLOCKING", true, false, false)]
    [InlineData("HOOK LOADED", true, false, false)]
    [InlineData("HOOK INSTALLED", false, true, false)]
    [InlineData("TRUST REQUIRED", false, true, false)]
    [InlineData("DETECTED", false, true, false)]
    [InlineData("AUDIT ONLY", false, true, false)]
    [InlineData("DEGRADED", false, false, true)]
    [InlineData("OFFLINE", false, false, true)]
    [InlineData("FAIL", false, false, true)]
    [InlineData("NOT DETECTED", false, false, false)]
    public void Protected_agent_tone_matches_hook_state(string status, bool ok, bool warn, bool fail)
    {
        var agent = new ProtectedAgent("opencode", @"C:\temp", status, "detail");

        Assert.Equal(ok, agent.ToneOk);
        Assert.Equal(warn, agent.ToneWarn);
        Assert.Equal(fail, agent.ToneFail);
        Assert.Equal(!ok && !warn && !fail, agent.ToneIdle);
    }

    private sealed class ShieldClient(ProtectionStatus status) : IServiceRequestClient
    {
        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            object result = command switch
            {
                IpcCommandTypes.RulesQuery => new FirewallRulesSnapshot
                {
                    Capability = new FirewallCapabilityReport
                    {
                        Status = FirewallCapabilityStatus.Available,
                        ManagedRulesReadable = true,
                        ManagedRuleCount = 0,
                    },
                    Rules = [],
                    WritesEnabled = true,
                },
                IpcCommandTypes.ProtectionStatus => status,
                _ => throw new ServiceUnavailableException(IpcErrorCodes.NotSupported, "not supported"),
            };

            return Task.FromResult((T)result);
        }
    }

    private sealed class OfflineClient : IServiceRequestClient
    {
        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken) =>
            throw new ServiceUnavailableException(IpcErrorCodes.ServiceUnavailable, "offline");
    }
    private sealed class FakeTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new FakeTimer(interval);

        private sealed class FakeTimer(TimeSpan interval) : IUiTimer
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
