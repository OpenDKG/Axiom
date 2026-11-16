// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Protection;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// The rule status line is a result, not a second read-only banner: it must never contradict the
/// live write gate (GUI-LOW, stale "Writes are disabled" after enabling the shield).
/// </summary>
public sealed class FirewallWriteGateTests
{
    [Fact]
    public async Task Enabling_and_disabling_the_shield_keeps_the_write_hint_truthful()
    {
        var client = new StatefulClient(Enabled: false, WriteGateOpen: false);
        var page = new FirewallPageViewModel(client, new ConfirmingInteraction());
        var changed = new List<string>();
        page.PropertyChanged += (_, e) => changed.Add(e.PropertyName ?? string.Empty);

        await WaitUntilAsync(() => !page.ShieldEnabled && !page.WritesEnabled);
        Assert.Equal(string.Empty, page.NewRuleStatusText);
        Assert.Contains("Turn on Axiom Shield", page.NewRuleWriteHint, StringComparison.Ordinal);
        Assert.Equal("READ-ONLY", page.NoticeBadgeText);

        await page.ToggleShieldCommand.ExecuteAsync(null);
        await WaitUntilAsync(() => page.ShieldEnabled && page.WritesEnabled);

        Assert.Equal(string.Empty, page.NewRuleStatusText);
        Assert.Contains("Axiom Shield is on", page.NewRuleWriteHint, StringComparison.Ordinal);
        Assert.DoesNotContain("Writes are disabled", page.NewRuleStatusText, StringComparison.Ordinal);
        Assert.Equal("SHIELD ON", page.NoticeBadgeText);
        Assert.Contains(nameof(FirewallPageViewModel.NewRuleWriteHint), changed);

        await page.ToggleShieldCommand.ExecuteAsync(null);
        await WaitUntilAsync(() => !page.ShieldEnabled && !page.WritesEnabled);

        Assert.Equal(string.Empty, page.NewRuleStatusText);
        Assert.Contains("Turn on Axiom Shield", page.NewRuleWriteHint, StringComparison.Ordinal);
        Assert.Single(client.EnableCalls);
    }

    [Fact]
    public async Task An_authorization_failure_stays_read_only_and_shows_the_error()
    {
        var client = new StatefulClient(Enabled: false, WriteGateOpen: false)
        {
            EnableFailure = new ServiceUnavailableException(
                IpcErrorCodes.Unauthorized,
                "administrator approval was denied"),
        };
        var page = new FirewallPageViewModel(client, new ConfirmingInteraction());

        await WaitUntilAsync(() => !page.WritesEnabled);
        await page.ToggleShieldCommand.ExecuteAsync(null);
        await WaitUntilAsync(() => page.ShieldStatusText.Contains("denied", StringComparison.Ordinal));

        Assert.False(page.ShieldEnabled);
        Assert.False(page.WritesEnabled);
        Assert.Equal(string.Empty, page.NewRuleStatusText);
        Assert.Contains("Turn on Axiom Shield", page.NewRuleWriteHint, StringComparison.Ordinal);
        Assert.Contains("denied", page.ShieldStatusText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Protection_enabled_does_not_imply_the_write_gate_is_open()
    {
        var client = new StatefulClient(Enabled: true, WriteGateOpen: false);
        var page = new FirewallPageViewModel(client, new ConfirmingInteraction());

        await WaitUntilAsync(() => page.ShieldEnabled);

        Assert.False(page.WritesEnabled);
        Assert.Equal("READ-ONLY", page.NoticeBadgeText);
        Assert.Contains("did not open", page.NoticeText, StringComparison.Ordinal);
        Assert.Contains("write gate", page.NewRuleWriteHint, StringComparison.Ordinal);
        Assert.DoesNotContain("Turn on Axiom Shield", page.NewRuleWriteHint, StringComparison.Ordinal);
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!condition() && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        Assert.True(condition(), "condition was not reached before the deadline");
    }

    private sealed class StatefulClient(bool Enabled, bool WriteGateOpen) : IServiceRequestClient
    {
        private bool _enabled = Enabled;
        private bool _writeGateOpen = WriteGateOpen;

        public Exception? EnableFailure { get; init; }

        public List<string> EnableCalls { get; } = [];

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
                    WritesEnabled = _writeGateOpen,
                },
                IpcCommandTypes.ProtectionStatus => Status(),
                IpcCommandTypes.ProtectionEnable => Enable(),
                IpcCommandTypes.ProtectionDisable => Disable(),
                _ => throw new ServiceUnavailableException(IpcErrorCodes.NotSupported, "not supported"),
            };

            return Task.FromResult((T)result);
        }

        private ProtectionStatus Status() => new()
        {
            Enabled = _enabled,
            ServiceElevated = true,
            WriteGateOpen = _writeGateOpen,
            AccountName = "root",
            DefaultPolicy = "ask",
            Pending = [],
            Decisions = [],
            AgentPaths = [],
            OwnedRuleCount = 0,
        };

        private ProtectionStatus Enable()
        {
            EnableCalls.Add(IpcCommandTypes.ProtectionEnable);
            if (EnableFailure is not null)
            {
                // The real client throws ServiceUnavailableException; mirror that shape here.
                throw EnableFailure;
            }

            _enabled = true;
            _writeGateOpen = true;
            return Status();
        }

        private ProtectionStatus Disable()
        {
            _enabled = false;
            _writeGateOpen = false;
            return Status();
        }
    }

    private sealed class ConfirmingInteraction : IUserInteraction
    {
        public Task<bool> ConfirmAsync(
            string title,
            string message,
            string confirmLabel,
            bool destructive,
            CancellationToken cancellationToken) => Task.FromResult(true);

        public Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task ShowDocumentAsync(string title, string document, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<string?> PickSaveFileAsync(
            string suggestedFileName,
            string extension,
            string typeName,
            CancellationToken cancellationToken) => Task.FromResult<string?>(null);

        public Task<string?> PickOpenFileAsync(
            string title,
            string extension,
            string typeName,
            CancellationToken cancellationToken) => Task.FromResult<string?>(null);

        public Task<string?> PickFolderAsync(string title, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task CopyTextAsync(string text, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task OpenExternalAsync(string url, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
