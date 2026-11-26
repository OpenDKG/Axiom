// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Reflection;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Protection;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// Maintainer ruling (v1.x): a daemon that does not answer is UNKNOWN, never protected, and no
/// surface keeps a stale or hardcoded protected/verified state. These tests drive the shell with
/// Network Control selected (the global header then shows Overview.StatusText from the shell, not
/// from an active dashboard) through daemon running -> stopped -> back. Off Windows only; Windows
/// keeps its behaviour.
/// </summary>
[Collection(DaemonStoppedStaleStateSerial.Name)]
public sealed class DaemonStoppedStaleStateTests
{
    [Fact]
    public async Task Header_and_shield_control_go_unknown_and_neutral_when_the_daemon_stops()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var client = new DaemonClient();
        var ui = DispatchProxy.Create<IUserInteraction, RecordingInteraction>();
        var shell = NewShell(client, ui);
        try
        {
            shell.SelectedPage = shell.Firewall;
            var page = shell.Firewall;
            await shell.ProbeProtectionAsync(force: true);
            Assert.Equal("Disable protection", page.ShieldActionText);
            Assert.Contains("firewall writes enabled", shell.Overview.StatusText, StringComparison.Ordinal);

            var raised = new List<string?>();
            page.PropertyChanged += (_, e) => raised.Add(e.PropertyName);

            client.Failure = new ServiceUnavailableException(IpcErrorCodes.ServiceUnavailable, "service offline");
            await shell.ProbeProtectionAsync(force: true);

            // SYSTEM STATUS header: unknown, never "active" or "writes enabled".
            Assert.Contains("unknown", shell.Overview.StatusText, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Protection active", shell.Overview.StatusText, StringComparison.Ordinal);
            Assert.DoesNotContain("writes enabled", shell.Overview.StatusText, StringComparison.Ordinal);

            // The shield control offers no on/off action and the binding is told so.
            Assert.Equal("Check protection", page.ShieldActionText);
            Assert.Contains(nameof(FirewallPageViewModel.ShieldActionText), raised);

            // Pressing it while the state is unknown only re-reads: no disable/enable request,
            // no confirmation dialog implying a known state.
            client.Commands.Clear();
            await page.ToggleShieldCommand.ExecuteAsync(null);
            Assert.DoesNotContain(IpcCommandTypes.ProtectionDisable, client.Commands);
            Assert.DoesNotContain(IpcCommandTypes.ProtectionEnable, client.Commands);
            Assert.Empty(((RecordingInteraction)(object)ui).Confirmations);
            Assert.Contains(IpcCommandTypes.ProtectionStatus, client.Commands);
            Assert.Equal("Check protection", page.ShieldActionText);

            // Daemon back: the same button re-reads and the known state returns everywhere.
            client.Failure = null;
            client.Commands.Clear();
            await page.ToggleShieldCommand.ExecuteAsync(null);
            Assert.DoesNotContain(IpcCommandTypes.ProtectionDisable, client.Commands);
            Assert.DoesNotContain(IpcCommandTypes.ProtectionEnable, client.Commands);
            Assert.Empty(((RecordingInteraction)(object)ui).Confirmations);
            Assert.Equal("Disable protection", page.ShieldActionText);
            Assert.Equal("SHIELD ON", shell.StatusFirewallBadgeText);
            Assert.Contains("Protection active", shell.Overview.StatusText, StringComparison.Ordinal);
        }
        finally
        {
            shell.Dispose();
        }
    }

    [Fact]
    public async Task Header_says_unknown_when_the_monitor_fails_with_the_daemon()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var client = new DaemonClient();
        var shell = NewShell(client);
        try
        {
            shell.SelectedPage = shell.Firewall;
            await shell.ProbeProtectionAsync(force: true);
            await PollMonitorAsync(shell);
            Assert.Contains("Protection active", shell.Overview.StatusText, StringComparison.Ordinal);

            // In service mode the connection monitor reads the same daemon, so it fails too
            // (VM shot lx-11: "Monitor unavailable: Service unavailable: …"). The header must still
            // say the protection state is unknown, not only that the monitor is unavailable.
            client.Failure = new ServiceUnavailableException(
                IpcErrorCodes.ServiceUnavailable,
                "Service unavailable: The service did not respond in time.");
            await PollMonitorAsync(shell);
            await shell.ProbeProtectionAsync(force: true);
            Assert.Contains("Protection status unknown", shell.Overview.StatusText, StringComparison.Ordinal);
            Assert.Contains("Monitor unavailable", shell.Overview.StatusText, StringComparison.Ordinal);
            Assert.DoesNotContain("Protection active", shell.Overview.StatusText, StringComparison.Ordinal);
            Assert.DoesNotContain("writes enabled", shell.Overview.StatusText, StringComparison.Ordinal);

            client.Failure = null;
            await PollMonitorAsync(shell);
            await shell.ProbeProtectionAsync(force: true);
            Assert.Contains("Protection active", shell.Overview.StatusText, StringComparison.Ordinal);
        }
        finally
        {
            shell.Dispose();
        }
    }

    /// <summary>Runs one connection-monitor poll (the shell's 1 s tick) without a real timer.</summary>
    private static Task PollMonitorAsync(ShellViewModel shell)
    {
        var monitor = (ConnectionMonitor)typeof(ShellViewModel)
            .GetField("_monitor", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(shell)!;
        return monitor.PollAsync();
    }

    [Fact]
    public async Task Owned_rules_stay_visible_as_last_known_but_never_applied_while_the_daemon_is_down()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await TestAppBuilder.RunOnUiThreadAsync(async () =>
        {
        var client = new DaemonClient();
        var shell = NewShell(client);
        try
        {
            shell.SelectedPage = shell.Firewall;
            var page = shell.Firewall;
            await shell.ProbeProtectionAsync(force: true);
            var row = Assert.Single(page.Rules);
            Assert.StartsWith("Applied", row.StateText, StringComparison.Ordinal);
            Assert.Equal("1", page.OwnedRuleCountText);

            client.Failure = new ServiceUnavailableException(IpcErrorCodes.ServiceUnavailable, "service offline");
            await shell.ProbeProtectionAsync(force: true);

            // The last-read row stays visible, its state is not presented as current.
            row = Assert.Single(page.Rules);
            Assert.Equal("/usr/bin/curl", row.AppPath);
            Assert.Equal(FirewallRuleRow.LastKnownStateText, row.StateText);
            Assert.Equal("Unknown (last known)", row.StateText);
            Assert.DoesNotContain("Applied", row.StateText, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("verified", row.StateText, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("proven", row.StateText, StringComparison.OrdinalIgnoreCase);

            // Count texts: no current-looking "N owned rules read at"; the note explains why.
            Assert.Equal("—", page.OwnedRuleCountText);
            Assert.Contains("last known", page.StatusText, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("unknown", page.StatusText, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("owned rules read at", page.StatusText, StringComparison.Ordinal);
            Assert.Contains("did not answer", page.CapabilityDetail, StringComparison.Ordinal);
            Assert.DoesNotContain("rule(s)", shell.StatusFirewallText, StringComparison.Ordinal);

            // Daemon back: the next rules read replaces the last-known rows with the live state.
            client.Failure = null;
            await shell.ProbeProtectionAsync(force: true);
            page.RefreshEnforcementIfStale(page.LastEnforcementRefreshUtc + FirewallPageViewModel.EnforcementRefreshInterval);
            row = Assert.Single(page.Rules);
            Assert.StartsWith("Applied", row.StateText, StringComparison.Ordinal);
            Assert.Equal("1", page.OwnedRuleCountText);
            Assert.Contains("owned rules read at", page.StatusText, StringComparison.Ordinal);
        }
        finally
        {
            shell.Dispose();
        }
        });
    }

    [Fact]
    public async Task Header_footer_and_page_agree_on_enforcement_after_the_daemon_returns()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var client = new DaemonClient();
        var shell = NewShell(client);
        try
        {
            shell.SelectedPage = shell.Firewall;
            var page = shell.Firewall;
            await shell.ProbeProtectionAsync(force: true);
            AssertOneAnswer(shell, page);
            Assert.True(page.Enforcement.IsEnforcementVerified);

            client.Failure = new ServiceUnavailableException(IpcErrorCodes.ServiceUnavailable, "service offline");
            await shell.ProbeProtectionAsync(force: true);
            AssertOneAnswer(shell, page);

            // Daemon back, the filter has not yet acknowledged the generation it republished.
            client.Failure = null;
            client.FilterState = FilterEnforcementState.Pending;
            await shell.ProbeProtectionAsync(force: true);
            AssertOneAnswer(shell, page);
            Assert.False(page.Enforcement.IsEnforcementVerified);

            // The page's own periodic re-read sees the acknowledgement: header and footer follow
            // in the same update, not one poll later.
            client.FilterState = FilterEnforcementState.Verified;
            page.RefreshEnforcementIfStale(page.LastEnforcementRefreshUtc + FirewallPageViewModel.EnforcementRefreshInterval);
            Assert.True(page.Enforcement.IsEnforcementVerified);
            AssertOneAnswer(shell, page);

            // And back to pending (filter re-handover): no surface keeps the verified claim.
            client.FilterState = FilterEnforcementState.Pending;
            page.RefreshEnforcementIfStale(page.LastEnforcementRefreshUtc + FirewallPageViewModel.EnforcementRefreshInterval);
            Assert.False(page.Enforcement.IsEnforcementVerified);
            AssertOneAnswer(shell, page);
        }
        finally
        {
            shell.Dispose();
        }
    }

    /// <summary>
    /// The SYSTEM STATUS header, the footer and the Network Control filter line must state the
    /// same enforcement answer: verified everywhere, or not verified everywhere with the page's
    /// reason. Unknown (no answer) counts as not verified.
    /// </summary>
    private static void AssertOneAnswer(ShellViewModel shell, FirewallPageViewModel page)
    {
        var header = shell.Overview.StatusText;
        var footer = shell.StatusFirewallText + " | " + shell.StatusSourceText;
        if (page.ShieldLevel is null)
        {
            Assert.Contains("unknown", header, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Protection active", header, StringComparison.Ordinal);
            Assert.Equal("UNKNOWN", shell.StatusFirewallBadgeText);
            Assert.DoesNotContain("verified", page.FilterConnectionText, StringComparison.OrdinalIgnoreCase);
            return;
        }

        if (page.Enforcement.IsEnforcementVerified)
        {
            Assert.Contains("verified", page.FilterConnectionText, StringComparison.Ordinal);
            Assert.DoesNotContain("not verified", header, StringComparison.Ordinal);
            Assert.DoesNotContain("not acknowledged", header, StringComparison.Ordinal);
            Assert.DoesNotContain("not verified", footer, StringComparison.Ordinal);
        }
        else
        {
            Assert.DoesNotContain(" verified at", page.FilterConnectionText, StringComparison.Ordinal);
            Assert.Contains("not verified", header, StringComparison.Ordinal);
            Assert.Contains(page.Enforcement.NotVerifiedReason, header, StringComparison.Ordinal);
            Assert.Contains("not verified", footer, StringComparison.Ordinal);
        }
    }

    private static ShellViewModel NewShell(DaemonClient client, IUserInteraction? ui = null) => new(
        new ServiceSnapshotSource(client),
        new NoopTimerFactory(),
        serviceProbe: new ServiceStatusProbe(client),
        serviceClient: client,
        userInteraction: ui,
        uiModeService: new FixedUiModeService(UiMode.Advanced));

    /// <summary>Fake axiomd: shield on, write gate open, one Axiom rule, filter verified.</summary>
    internal sealed class DaemonClient : IServiceRequestClient
    {
        public Exception? Failure { get; set; }

        public List<string> Commands { get; } = [];

        public FilterEnforcementState FilterState { get; set; } = FilterEnforcementState.Verified;

        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            Commands.Add(command);
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
                    OwnedRuleCount = 1,
                },
                IpcCommandTypes.RulesQuery => new FirewallRulesSnapshot
                {
                    Capability = new FirewallCapabilityReport
                    {
                        Status = FirewallCapabilityStatus.Available,
                        ManagedRulesReadable = true,
                        ManagedRuleCount = 1,
                        FilterEnforcement = new FilterEnforcementReport
                        {
                            State = FilterState,
                            Connected = true,
                            PublishedGeneration = 7,
                            Generation = 7,
                            AckedGeneration = FilterState == FilterEnforcementState.Verified ? 7 : 6,
                            LastAckUtc = DateTimeOffset.UtcNow,
                        },
                    },
                    Rules = [OwnedRule()],
                    WritesEnabled = true,
                },
                IpcCommandTypes.Snapshot => new Axiom.Contracts.Monitoring.ConnectionSnapshot
                {
                    CapturedUtc = DateTimeOffset.UtcNow,
                    Connections = [],
                    ProcessCount = 0,
                    SourceName = "fake axiomd",
                },
                IpcCommandTypes.Capabilities => new ServiceCapabilities
                {
                    ProtocolVersion = 1,
                    Commands = [],
                    Monitoring = true,
                    FirewallWrites = false,
                    Milestone = "test",
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
                _ => throw new ServiceUnavailableException(IpcErrorCodes.NotSupported, "not supported"),
            };

            return Task.FromResult((T)result);
        }

        private static ManagedRule OwnedRule()
        {
            var id = Guid.Parse("3f2b8c1e-0000-4000-8000-000000000001");
            return new ManagedRule
            {
                ManagedRuleId = id,
                OsRuleName = "Axiom::curl",
                Spec = new RuleSpec
                {
                    ManagedRuleId = id,
                    AppPath = "/usr/bin/curl",
                    Direction = FirewallDirection.Outbound,
                    Action = FirewallAction.Block,
                    CreatedBy = "test",
                },
                State = RuleState.Applied,
                LastVerifiedUtc = DateTimeOffset.UtcNow,
            };
        }
    }

    /// <summary>Records confirmation prompts; confirms everything so a wrong path would act.</summary>
    public class RecordingInteraction : DispatchProxy
    {
        public List<string> Confirmations { get; } = [];

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod?.Name == nameof(IUserInteraction.ConfirmAsync))
            {
                Confirmations.Add((string)args![0]!);
                return Task.FromResult(true);
            }

            return targetMethod?.ReturnType == typeof(Task) ? Task.CompletedTask : null;
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

/// <summary>
/// These shell tests run alone, after the parallel classes: run alongside the headless UI thread's
/// first initialization they raced Avalonia's static routed-event registration and crashed the
/// test host ("An item with the same key has already been added. Key: Avalonia.Input.InputElement").
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class DaemonStoppedStaleStateSerial
{
    public const string Name = "Daemon stopped stale state (not parallel)";
}
