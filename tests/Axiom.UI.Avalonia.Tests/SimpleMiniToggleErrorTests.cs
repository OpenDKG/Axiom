// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Privacy;
using Axiom.Contracts.Protection;
using Axiom.Presentation;
using Avalonia.Threading;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// Simple and Mini home toggles must not show optimistic Privacy state and must surface Shield and
/// Privacy failures inline instead of hiding them behind active status text.
/// </summary>
public sealed class SimpleMiniToggleErrorTests
{
    [Fact]
    public async Task Privacy_enable_failure_leaves_off_state_and_shows_error_on_simple()
    {
        await Dispatcher.UIThread.InvokeAsync(async () =>
        {
            var client = new FailingClient { FailPrivacyConfigure = true };
            using var shell = NewShell(client);
            Assert.False(shell.PrivacyShield.Enabled);

            await shell.SimpleHome.TogglePrivacyCommand.ExecuteAsync(null);

            Assert.False(shell.PrivacyShield.Enabled);
            Assert.Equal("Turn On", shell.SimpleHome.PrivacyActionText);
            Assert.True(shell.SimpleHome.HasActionError);
            Assert.Contains("Could not turn on Privacy Shield", shell.SimpleHome.ActionErrorText, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Privacy_enable_failure_leaves_off_state_and_shows_error_on_mini()
    {
        await Dispatcher.UIThread.InvokeAsync(async () =>
        {
            var client = new FailingClient { FailPrivacyConfigure = true };
            using var shell = NewShell(client);

            await shell.MiniHome.TogglePrivacyCommand.ExecuteAsync(null);

            Assert.False(shell.PrivacyShield.Enabled);
            Assert.True(shell.MiniHome.HasActionError);
            Assert.Contains("Could not turn on Privacy Shield", shell.MiniHome.ActionErrorText, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Shield_disable_failure_shows_inline_error_on_simple_and_mini()
    {
        await Dispatcher.UIThread.InvokeAsync(async () =>
        {
            var client = new FailingClient { ProtectionEnabled = true, FailProtectionDisable = true };
            using var shell = NewShell(client);
            await shell.ProbeProtectionAsync(force: true);
            Assert.True(shell.Firewall.ProtectionKnown);
            Assert.True(shell.Firewall.ShieldEnabled);

            await shell.SimpleHome.ToggleShieldCommand.ExecuteAsync(null);
            Assert.True(shell.SimpleHome.HasActionError);
            Assert.Contains("failed", shell.SimpleHome.ActionErrorText, StringComparison.OrdinalIgnoreCase);

            await shell.MiniHome.ToggleShieldCommand.ExecuteAsync(null);
            Assert.True(shell.MiniHome.HasActionError);
            Assert.Contains("failed", shell.MiniHome.ActionErrorText, StringComparison.OrdinalIgnoreCase);
        });
    }

    private static ShellViewModel NewShell(FailingClient client) =>
        new(
            new ServiceSnapshotSource(client),
            new NoopTimerFactory(),
            serviceClient: client,
            userInteraction: new ConfirmingInteraction(),
            uiModeService: new FixedUiModeService(UiMode.Simple));

    private sealed class FailingClient : IServiceRequestClient
    {
        public bool ProtectionEnabled { get; set; }

        public bool FailPrivacyConfigure { get; set; }

        public bool FailProtectionDisable { get; set; }

        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            if (command == IpcCommandTypes.ProtectionStatus)
            {
                return Task.FromResult((T)(object)new ProtectionStatus
                {
                    Enabled = ProtectionEnabled,
                    ServiceElevated = true,
                    WriteGateOpen = true,
                    AccountName = "root",
                    DefaultPolicy = "ask",
                    Pending = [],
                    Decisions = [],
                    AgentPaths = [],
                    OwnedRuleCount = 0,
                });
            }

            if (command == IpcCommandTypes.PrivacyConfigure && FailPrivacyConfigure)
            {
                return Task.FromException<T>(new InvalidOperationException("privacy configure failed"));
            }

            if (command == IpcCommandTypes.PrivacyConfigure)
            {
                var enabled = payload is PrivacyShieldSettings settings && settings.Enabled;
                return Task.FromResult((T)(object)new PrivacyShieldStatus
                {
                    State = enabled ? "running" : "stopped",
                    Enabled = enabled,
                    Running = enabled,
                    Port = 53,
                    BindAddress = "127.0.0.1",
                    Upstream = "1.1.1.1",
                    Queries = 0,
                    Blocked = 0,
                    Allowed = 0,
                    Errors = 0,
                    RuleCount = 0,
                });
            }

            if (command == IpcCommandTypes.ProtectionDisable)
            {
                if (FailProtectionDisable)
                {
                    return Task.FromException<T>(new InvalidOperationException("disable failed"));
                }

                return Task.FromResult((T)(object)new ProtectionStatus
                {
                    Enabled = false,
                    ServiceElevated = true,
                    WriteGateOpen = true,
                    AccountName = "root",
                    DefaultPolicy = "ask",
                    Pending = [],
                    Decisions = [],
                    AgentPaths = [],
                    OwnedRuleCount = 0,
                });
            }

            if (command == IpcCommandTypes.RulesQuery)
            {
                return Task.FromResult((T)(object)new FirewallRulesSnapshot
                {
                    Capability = new FirewallCapabilityReport
                    {
                        Status = FirewallCapabilityStatus.Available,
                        ManagedRulesReadable = true,
                        ManagedRuleCount = 0,
                    },
                    Rules = [],
                });
            }

            return Task.FromException<T>(new ServiceUnavailableException(IpcErrorCodes.NotSupported, "not supported"));
        }
    }

    private sealed class ConfirmingInteraction : IUserInteraction
    {
        public Task<bool> ConfirmAsync(string title, string message, string confirmLabel, bool destructive, CancellationToken cancellationToken) =>
            Task.FromResult(true);

        public Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task ShowDocumentAsync(string title, string document, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<string?> PickSaveFileAsync(string suggestedFileName, string filterName, string extension, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task<string?> PickOpenFileAsync(string title, string filterName, string extension, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task<string?> PickFolderAsync(string title, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task CopyTextAsync(string text, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task OpenExternalAsync(string url, CancellationToken cancellationToken) => Task.CompletedTask;
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
