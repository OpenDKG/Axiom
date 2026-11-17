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
