// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Protection;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// Unblock on an owned-rule row must remove THAT row's rule (by its id), and the page may only
/// report the app as unblocked once a fresh rule list no longer shows it. A rule created over the
/// socket by another client (rule.apply with its own id) used to stay in force while the page
/// recorded "Allowed", because protection.decide only removes the id derived from the path.
/// </summary>
public sealed class UnblockRuleRowTests
{
    // Native path per OS; the fake service does not validate it.
    private static readonly string AppPath = OperatingSystem.IsWindows()
        ? @"C:\Program Files\Example\example.exe"
        : "/usr/bin/example";

    [Fact]
    public async Task Unblock_removes_a_foreign_id_rule_by_its_own_id_before_recording_allow()
    {
        var foreignId = Guid.NewGuid();
        var service = new FakeService(Rule(foreignId));
        var page = await OpenAsync(service);

        await page.UnblockRuleCommand.ExecuteAsync(Assert.Single(page.Rules));

        Assert.Equal([foreignId], service.RemovedIds);
        Assert.Empty(service.Rules);
        var decision = Assert.Single(service.Decisions);
        Assert.Equal(ProtectionDecisionAction.Allow, decision.Action);
        Assert.Contains("unblocked", page.StatusText, StringComparison.Ordinal);
        Assert.DoesNotContain("failed", page.StatusText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Refused_removal_says_so_and_records_no_allow_decision()
    {
        var foreignId = Guid.NewGuid();
        var service = new FakeService(Rule(foreignId)) { RefuseRemove = true };
        var page = await OpenAsync(service);

        await page.UnblockRuleCommand.ExecuteAsync(Assert.Single(page.Rules));

        Assert.Single(service.Rules);
        Assert.Empty(service.Decisions);
        Assert.Contains("Unblock failed", page.StatusText, StringComparison.Ordinal);
        Assert.Contains("No allow decision was recorded", page.StatusText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Removal_reported_but_rule_still_listed_is_not_reported_as_unblocked()
    {
        var foreignId = Guid.NewGuid();
        var service = new FakeService(Rule(foreignId)) { RemoveWithoutEffect = true };
        var page = await OpenAsync(service);

        await page.UnblockRuleCommand.ExecuteAsync(Assert.Single(page.Rules));

        Assert.Empty(service.Decisions);
        Assert.Contains("still listed", page.StatusText, StringComparison.Ordinal);
        Assert.DoesNotContain("unblocked", page.StatusText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task App_derived_rule_still_listed_after_the_decision_is_not_reported_as_unblocked()
    {
        var derivedId = RuleIdentity.ForApp(AppPath, FirewallDirection.Outbound);
        var service = new FakeService(Rule(derivedId)) { DecideLeavesRule = true };
        var page = await OpenAsync(service);

        await page.UnblockRuleCommand.ExecuteAsync(Assert.Single(page.Rules));

        Assert.Empty(service.RemovedIds);
        Assert.Contains("still listed", page.StatusText, StringComparison.Ordinal);
        Assert.DoesNotContain("unblocked (", page.StatusText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task App_derived_rule_is_unblocked_through_the_decision_and_confirmed()
    {
        var derivedId = RuleIdentity.ForApp(AppPath, FirewallDirection.Outbound);
        var service = new FakeService(Rule(derivedId));
        var page = await OpenAsync(service);

        await page.UnblockRuleCommand.ExecuteAsync(Assert.Single(page.Rules));

        Assert.Empty(service.RemovedIds);
        Assert.Empty(service.Rules);
        Assert.Single(service.Decisions);
        Assert.Contains("unblocked", page.StatusText, StringComparison.Ordinal);
    }

    private static async Task<FirewallPageViewModel> OpenAsync(FakeService service)
    {
        var page = new FirewallPageViewModel(service, new ConfirmingInteraction());
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while ((page.Rules.Count == 0 || !page.ShieldEnabled || page.IsBusy) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        Assert.Single(page.Rules);
        Assert.True(page.ShieldEnabled);
        return page;
    }

    private static ManagedRule Rule(Guid id) => new()
    {
        ManagedRuleId = id,
        OsRuleName = $"Axiom-{id:N}",
        State = RuleState.Applied,
        Spec = new RuleSpec
        {
            ManagedRuleId = id,
            AppPath = AppPath,
            Direction = FirewallDirection.Outbound,
            Action = FirewallAction.Block,
            Profiles = FirewallProfile.All,
            CreatedBy = "another-client",
        },
    };

    /// <summary>
    /// Behaves like the daemon: protection.decide removes only the id derived from the path, and
    /// rule.remove removes the given id (or is refused like a closed write gate).
    /// </summary>
    private sealed class FakeService(ManagedRule initial) : IServiceRequestClient
    {
        public List<ManagedRule> Rules { get; } = [initial];

        public List<ProtectionDecision> Decisions { get; } = [];

        public List<Guid> RemovedIds { get; } = [];

        public bool RefuseRemove { get; init; }

        public bool RemoveWithoutEffect { get; init; }

        public bool DecideLeavesRule { get; init; }

        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            lock (Rules)
            {
                if (command == IpcCommandTypes.RuleRemove && RefuseRemove)
                {
                    return Task.FromException<T>(new ServiceUnavailableException(
                        IpcErrorCodes.NotSupported,
                        "Firewall writes are disabled on this service."));
                }

                object result = command switch
                {
                    IpcCommandTypes.RulesQuery => new FirewallRulesSnapshot
                    {
                        Capability = new FirewallCapabilityReport
                        {
                            Status = FirewallCapabilityStatus.Available,
                            ManagedRulesReadable = true,
                            ManagedRuleCount = Rules.Count,
                        },
                        Rules = Rules.ToList(),
                        WritesEnabled = true,
                    },
                    IpcCommandTypes.ProtectionStatus => Status(null),
                    IpcCommandTypes.RuleRemove => Remove(((RuleReference)payload!).ManagedRuleId),
                    IpcCommandTypes.ProtectionDecide => Decide((ProtectionDecideRequest)payload!),
                    _ => throw new ServiceUnavailableException(IpcErrorCodes.NotSupported, "not supported"),
                };

                return Task.FromResult((T)result);
            }
        }

        private RuleApplyResult Remove(Guid id)
        {
            RemovedIds.Add(id);
            if (!RemoveWithoutEffect)
            {
                Rules.RemoveAll(rule => rule.ManagedRuleId == id);
            }

            return new RuleApplyResult { Success = true, ManagedRuleId = id, State = RuleState.Unknown };
        }

        private ProtectionStatus Decide(ProtectionDecideRequest request)
        {
            var derived = RuleIdentity.ForApp(request.AppPath, FirewallDirection.Outbound);
            if (!DecideLeavesRule)
            {
                Rules.RemoveAll(rule => rule.ManagedRuleId == derived);
            }

            Decisions.Add(new ProtectionDecision
            {
                AppPath = request.AppPath,
                AppName = request.AppName,
                Action = request.Action,
                DecidedUtc = DateTimeOffset.UtcNow,
            });
            return Status(null);
        }

        private ProtectionStatus Status(string? error) => new()
        {
            Enabled = true,
            ServiceElevated = true,
            WriteGateOpen = true,
            AccountName = "root",
            DefaultPolicy = "ask",
            Pending = [],
            Decisions = Decisions.ToList(),
            AgentPaths = [],
            OwnedRuleCount = Rules.Count,
            LastError = error,
        };
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
