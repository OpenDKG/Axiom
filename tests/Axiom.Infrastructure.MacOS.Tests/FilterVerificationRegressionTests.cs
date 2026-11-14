// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Axiom.Infrastructure.MacOS.Filter;

namespace Axiom.Infrastructure.MacOS.Tests;

/// <summary>
/// GitHub review #2 (5874573617) on PR #274, blocking findings MAC-1 and MAC-2. Every test here is
/// deterministic (fake clock, zero acknowledgement timeout, the filter's reports are injected
/// directly into <see cref="FilterStatus"/>); none waits on wall-clock time.
/// <para>
/// MAC-1: a <c>filter.rules</c> report with an error for the generation that was acknowledged
/// earlier must revoke <c>Verified</c>; per-rule verification must prove the expected rule in the
/// acknowledged effective table, not just the global generation.
/// </para>
/// <para>
/// MAC-2: recovery-only removal must use the same publish → bounded ack wait → state discipline as
/// normal removal and never answer with a verification timestamp for a file write.
/// </para>
/// </summary>
public sealed class FilterVerificationRegressionTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 12, 12, 0, 0, TimeSpan.Zero);

    private static FlowEvent RulesEvent(long generation, int applied = 0, string? error = null, params (string Id, string Reason)[] rejected)
    {
        var rejectedJson = string.Join(",", rejected.Select(entry => $"{{\"id\":\"{entry.Id}\",\"reason\":\"{entry.Reason}\"}}"));
        var errorJson = error is null ? "null" : $"\"{error}\"";
        return FlowEventParser.TryParse(string.Create(
            CultureInfo.InvariantCulture,
            $"{{\"type\":\"filter.rules\",\"generation\":{generation},\"applied\":{applied},\"rejected\":[{rejectedJson}],\"error\":{errorJson},\"dropped\":0}}"))!;
    }

    private static long PublishedGeneration(MacServicePaths paths) => FilterRulesFile.TryRead(paths.RulesFile)!.Generation;

    private static (MacServicePaths Paths, ManualTimeProvider Time, FilterStatus Status, MacFirewallPolicyAdapter Adapter) Harness(TempDirectory temp)
    {
        var paths = MacServicePaths.ForRoot(temp.Path);
        var time = new ManualTimeProvider(Start);
        var status = new FilterStatus();
        var adapter = new MacFirewallPolicyAdapter(paths, status, () => true, time, TimeSpan.Zero);
        return (paths, time, status, adapter);
    }

    private static bool Contains(FilterRuleTable? table, RuleSpec spec) =>
        table?.Rules.Any(rule => string.Equals(rule.Id, FilterRuleTable.ToFilterRule(spec).Id, StringComparison.OrdinalIgnoreCase)) == true;

    // ----- MAC-1: FilterStatus state semantics -----

    [Fact]
    public void SameGenerationErrorReportAfterAck_RevokesVerified()
    {
        var status = new FilterStatus();
        var connection = status.ClientConnected();
        status.RulesReported(connection, RulesEvent(5, applied: 1), Start);
        Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(5));

        // The file in place is rejected on re-evaluation (chmod g+w, truncated write, …): the
        // extension reports the generation still in force (5) together with the error.
        status.RulesReported(connection, RulesEvent(5, applied: 1, error: "group/world-writable (mode 664)"), Start.AddSeconds(1));

        Assert.NotEqual(FilterEnforcementState.Verified, status.Evaluate(5));
        var snapshot = status.Snapshot(5);
        Assert.False(snapshot.IsVerified);
        Assert.Equal("group/world-writable (mode 664)", snapshot.Rules?.Error);
    }

    [Fact]
    public void CleanCurrentAckAfterError_RestoresVerified()
    {
        var status = new FilterStatus();
        var connection = status.ClientConnected();
        status.RulesReported(connection, RulesEvent(5, applied: 1), Start);
        status.RulesReported(connection, RulesEvent(5, applied: 1, error: "invalid JSON"), Start.AddSeconds(1));
        Assert.NotEqual(FilterEnforcementState.Verified, status.Evaluate(5));

        // Only a newer, error-free report for the published generation on this connection restores it.
        status.RulesReported(connection, RulesEvent(5, applied: 1), Start.AddSeconds(2));
        Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(5));
        Assert.Equal(Start.AddSeconds(2), status.LastAckUtc);
    }

    [Fact]
    public void PreviousGenerationAck_DoesNotVerifyThePublishedOne()
    {
        var status = new FilterStatus();
        var connection = status.ClientConnected();
        status.RulesReported(connection, RulesEvent(6, applied: 1), Start);
        Assert.Equal(FilterEnforcementState.Pending, status.Evaluate(7));
        Assert.False(status.Snapshot(7).IsVerified);
    }

    [Fact]
    public void PreviousConnectionAck_DoesNotSurviveReconnect()
    {
        var status = new FilterStatus();
        var first = status.ClientConnected();
        status.RulesReported(first, RulesEvent(5, applied: 1), Start);
        Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(5));

        status.ClientDisconnected(first);
        Assert.Equal(FilterEnforcementState.Degraded, status.Evaluate(5));
        var second = status.ClientConnected();
        status.Hello(second, "1.0", 5, Start.AddSeconds(1));
        Assert.Equal(FilterEnforcementState.Pending, status.Evaluate(5));
        Assert.False(status.Snapshot(5).IsVerified);

        status.RulesReported(second, RulesEvent(5, applied: 1), Start.AddSeconds(2));
        Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(5));
    }

    // ----- MAC-1: per-rule verification in the adapter -----

    [Fact]
    public async Task ExpectedRuleMissingOrMismatchedInTheAcknowledgedTable_IsNotVerified()
    {
        using var temp = new TempDirectory();
        var (paths, time, status, adapter) = Harness(temp);
        using (adapter)
        {
            var connection = status.ClientConnected();
            var curl = Specs.Block("/usr/bin/curl");
            await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            var generation = PublishedGeneration(paths);
            status.RulesReported(connection, RulesEvent(generation, applied: 1), time.GetUtcNow());
            Assert.True((await adapter.VerifyAsync(curl, CancellationToken.None)).EnforcementVerified);

            // Same generation on disk, but the expected rule is not in the table the filter runs.
            FilterRulesFile.WriteAtomic(paths.RulesFile, FilterRuleTable.Create([], generation));
            var missing = await adapter.VerifyAsync(curl, CancellationToken.None);
            Assert.False(missing.PresentInOs);
            Assert.False(missing.EnforcementVerified);
            Assert.Null(missing.EffectiveAction);

            // Same id and generation, different content (Allow instead of Block).
            FilterRulesFile.WriteAtomic(paths.RulesFile, FilterRuleTable.Create([curl with { Action = FirewallAction.Allow }], generation));
            var mismatched = await adapter.VerifyAsync(curl, CancellationToken.None);
            Assert.True(mismatched.PresentInOs);
            Assert.False(mismatched.MatchesSpec);
            Assert.False(mismatched.EnforcementVerified);
            Assert.Null(mismatched.EffectiveAction);
        }
    }

    [Fact]
    public async Task RejectedRulesFileAfterAVerifiedApply_DegradesRuleAndOverallStatus()
    {
        using var temp = new TempDirectory();
        var (paths, time, status, adapter) = Harness(temp);
        using (adapter)
        {
            var connection = status.ClientConnected();
            var curl = Specs.Block("/usr/bin/curl");
            await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            var generation = PublishedGeneration(paths);
            status.RulesReported(connection, RulesEvent(generation, applied: 1), time.GetUtcNow());
            Assert.Equal(RuleState.Applied, Assert.Single(await adapter.ListOwnedRulesAsync(CancellationToken.None)).State);

            // The extension re-evaluates the file in place and rejects it (same generation + error).
            time.Advance(TimeSpan.FromSeconds(1));
            status.RulesReported(connection, RulesEvent(generation, applied: 1, error: "group/world-writable (mode 664)"), time.GetUtcNow());

            Assert.NotEqual(RuleState.Applied, Assert.Single(await adapter.ListOwnedRulesAsync(CancellationToken.None)).State);

            var verify = await adapter.VerifyAsync(curl, CancellationToken.None);
            Assert.False(verify.EnforcementVerified);
            Assert.Null(verify.EffectiveAction);
            Assert.Contains(verify.Notes, note => note.Contains("rejected the rules file", StringComparison.Ordinal));

            var capabilities = await adapter.GetCapabilitiesAsync(CancellationToken.None);
            var enforcement = Assert.IsType<FilterEnforcementReport>(capabilities.FilterEnforcement);
            Assert.NotEqual(FilterEnforcementState.Verified, enforcement.State);
            Assert.Equal("group/world-writable (mode 664)", enforcement.FileError);
            Assert.NotNull(capabilities.Reason);
            Assert.Contains("rejected", capabilities.Reason, StringComparison.Ordinal);
            Assert.Equal(FirewallCapabilityStatus.Degraded, capabilities.Status);
            Assert.DoesNotContain(verify.Notes, note => note.Contains("acknowledged generation", StringComparison.Ordinal));
        }
    }

    // ----- MAC-2: recovery-only removal -----

    /// <summary>The recovery path is refused outside the daemon; the tests run it as the service host.</summary>
    private sealed class ServiceHostScope : IDisposable
    {
        private readonly string? _previous = Environment.GetEnvironmentVariable("AXIOM_SERVICE");

        public ServiceHostScope() => Environment.SetEnvironmentVariable("AXIOM_SERVICE", "1");

        public void Dispose() => Environment.SetEnvironmentVariable("AXIOM_SERVICE", _previous);
    }

    [Fact]
    public async Task RecoveryRemoval_ExtensionDisconnected_IsNotReportedVerified()
    {
        using var temp = new TempDirectory();
        using var host = new ServiceHostScope();
        var (paths, _, status, adapter) = Harness(temp);
        using (adapter)
        {
            var curl = Specs.Block("/usr/bin/curl");
            await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            var connection = status.ClientConnected();
            status.ClientDisconnected(connection);

            var removal = await adapter.RemoveCapturedOwnedRuleAsync(curl.ManagedRuleId, FirewallDirection.Outbound, CancellationToken.None);

            Assert.Null(removal.VerifiedUtc);
            Assert.False(removal.Success);
            Assert.Equal(RuleState.Pending, removal.State);
            Assert.Equal("filter.disconnected", removal.ErrorCode);
            Assert.Contains("not verified", removal.ErrorMessage, StringComparison.Ordinal);
            // The table was republished without the rule; what is unknown is whether the filter applied it.
            Assert.False(Contains(FilterRulesFile.TryRead(paths.RulesFile), curl));
        }
    }

    [Fact]
    public async Task RecoveryRemoval_StaleGenerationReport_StaysPending()
    {
        using var temp = new TempDirectory();
        using var host = new ServiceHostScope();
        var (paths, time, status, adapter) = Harness(temp);
        using (adapter)
        {
            var connection = status.ClientConnected();
            var curl = Specs.Block("/usr/bin/curl");
            await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            status.RulesReported(connection, RulesEvent(PublishedGeneration(paths), applied: 1), time.GetUtcNow());

            // The removal publishes the next generation; the filter never acknowledges it (ack for N-1 only).
            var removal = await adapter.RemoveCapturedOwnedRuleAsync(curl.ManagedRuleId, FirewallDirection.Outbound, CancellationToken.None);

            Assert.Null(removal.VerifiedUtc);
            Assert.False(removal.Success);
            Assert.Equal(RuleState.Pending, removal.State);
            Assert.Equal("filter.ack_pending", removal.ErrorCode);
            Assert.Contains(PublishedGeneration(paths).ToString(CultureInfo.InvariantCulture), removal.ErrorMessage, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task RecoveryRemoval_RejectedRulesFile_IsNotReportedComplete()
    {
        using var temp = new TempDirectory();
        using var host = new ServiceHostScope();
        var (paths, time, status, adapter) = Harness(temp);
        using (adapter)
        {
            var connection = status.ClientConnected();
            var curl = Specs.Block("/usr/bin/curl");
            await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            var generation = PublishedGeneration(paths);
            status.RulesReported(connection, RulesEvent(generation, applied: 1), time.GetUtcNow());

            // The filter rejects the republished file and keeps the old generation (report at the publish time).
            status.RulesReported(connection, RulesEvent(generation, applied: 1, error: "owned by uid 501, expected uid 0"), time.GetUtcNow());
            var removal = await adapter.RemoveCapturedOwnedRuleAsync(curl.ManagedRuleId, FirewallDirection.Outbound, CancellationToken.None);

            Assert.Null(removal.VerifiedUtc);
            Assert.False(removal.Success);
            Assert.Equal("filter.file_rejected", removal.ErrorCode);
            Assert.NotEqual(RuleState.Desired, removal.State);
        }
    }

    [Fact]
    public async Task RecoveryRemoval_RetryAfterReconnect_IsIdempotentAndVerifiedByTheAck()
    {
        using var temp = new TempDirectory();
        using var host = new ServiceHostScope();
        var (paths, time, status, adapter) = Harness(temp);
        using (adapter)
        {
            var connection = status.ClientConnected();
            var curl = Specs.Block("/usr/bin/curl");
            var nc = Specs.Block("/usr/bin/nc");
            await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            await adapter.UpsertOwnedRuleAsync(nc, CancellationToken.None);
            status.RulesReported(connection, RulesEvent(PublishedGeneration(paths), applied: 2), time.GetUtcNow());

            // Extension goes away (timeout / crash): the first attempt publishes but cannot verify.
            status.ClientDisconnected(connection);
            var first = await adapter.RemoveCapturedOwnedRuleAsync(curl.ManagedRuleId, FirewallDirection.Outbound, CancellationToken.None);
            Assert.False(first.Success);
            Assert.Null(first.VerifiedUtc);
            var afterFirst = FilterRulesFile.TryRead(paths.RulesFile);
            Assert.False(Contains(afterFirst, curl));
            Assert.True(Contains(afterFirst, nc), "unrelated rules stay untouched");

            // Not "absent" for the recovery controller until the filter acknowledged the table without it.
            Assert.NotEqual(OwnedRulePresence.Absent, await adapter.InspectOwnedRuleAsync(curl.ManagedRuleId, FirewallDirection.Outbound, CancellationToken.None));

            // Reconnect: the daemon republishes on connect, the new instance acknowledges.
            var reconnected = status.ClientConnected();
            var republished = await adapter.PublishAsync(CancellationToken.None);
            time.Advance(TimeSpan.FromSeconds(3));
            var ackTime = time.GetUtcNow();
            status.RulesReported(reconnected, RulesEvent(republished, applied: 1), ackTime);

            // Retry is idempotent: nothing is rewritten, the acknowledged table proves the absence.
            var generationBefore = PublishedGeneration(paths);
            var retry = await adapter.RemoveCapturedOwnedRuleAsync(curl.ManagedRuleId, FirewallDirection.Outbound, CancellationToken.None);
            Assert.True(retry.Success);
            Assert.Equal(RuleState.Desired, retry.State);
            Assert.Equal(ackTime, retry.VerifiedUtc);
            Assert.Equal(generationBefore, PublishedGeneration(paths));
            Assert.True(Contains(FilterRulesFile.TryRead(paths.RulesFile), nc));
            Assert.Equal(OwnedRulePresence.Absent, await adapter.InspectOwnedRuleAsync(curl.ManagedRuleId, FirewallDirection.Outbound, CancellationToken.None));
            Assert.Equal(nc.ManagedRuleId, Assert.Single(await adapter.ListOwnedRulesAsync(CancellationToken.None)).ManagedRuleId);
        }
    }

    [Fact]
    public async Task RecoveryRemoval_NeverStampsVerifiedUtcFromTheClockAlone()
    {
        using var temp = new TempDirectory();
        using var host = new ServiceHostScope();
        var (_, time, status, adapter) = Harness(temp);
        using (adapter)
        {
            var curl = Specs.Block("/usr/bin/curl");
            await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            var connection = status.ClientConnected();
            status.Hello(connection, "1.0", 1, time.GetUtcNow());

            // Connected, nothing acknowledged: a VerifiedUtc equal to "now" would be a file-write timestamp.
            var removal = await adapter.RemoveCapturedOwnedRuleAsync(curl.ManagedRuleId, FirewallDirection.Outbound, CancellationToken.None);
            Assert.Null(removal.VerifiedUtc);
            Assert.NotEqual(time.GetUtcNow(), removal.VerifiedUtc);
        }
    }

    // ----- MAC-1: the filter's own list of enforced ids (optional ruleIds field) -----

    private static FlowEvent RulesEventWithIds(long generation, string? error, params string[] ids) =>
        FlowEventParser.TryParse(string.Create(
            CultureInfo.InvariantCulture,
            $"{{\"type\":\"filter.rules\",\"generation\":{generation},\"applied\":{ids.Length},\"rejected\":[],\"error\":{(error is null ? "null" : "\"" + error + "\"")},\"ruleIds\":[{string.Join(",", ids.Select(id => "\"" + id + "\""))}],\"dropped\":0}}"))!;

    [Fact]
    public void Parser_ReadsRuleIds_AndTreatsAMissingListAsUnknown()
    {
        var withIds = RulesEventWithIds(4, null, "a", "b");
        Assert.Equal(["a", "b"], withIds.RuleIds);
        Assert.Null(RulesEvent(4, applied: 2).RuleIds);
    }

    [Fact]
    public async Task AcknowledgedTableThatDoesNotListTheRule_IsNotVerified()
    {
        using var temp = new TempDirectory();
        var (paths, time, status, adapter) = Harness(temp);
        using (adapter)
        {
            var connection = status.ClientConnected();
            var curl = Specs.Block("/usr/bin/curl");
            await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            var generation = PublishedGeneration(paths);
            var id = FilterRuleTable.ToFilterRule(curl).Id;

            // Clean ack of the right generation, but the filter's effective table lacks the rule.
            status.RulesReported(connection, RulesEventWithIds(generation, null), time.GetUtcNow());
            Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(generation));
            Assert.False((await adapter.VerifyAsync(curl, CancellationToken.None)).EnforcementVerified);
            Assert.Equal(RuleState.Failed, Assert.Single(await adapter.ListOwnedRulesAsync(CancellationToken.None)).State);

            // The filter lists it: verified.
            status.RulesReported(connection, RulesEventWithIds(generation, null, id), time.GetUtcNow());
            var verify = await adapter.VerifyAsync(curl, CancellationToken.None);
            Assert.True(verify.EnforcementVerified);
            Assert.Equal(FirewallAction.Block, verify.EffectiveAction);
        }
    }

    [Fact]
    public async Task DisabledRule_IsVerifiedWhenTheFilterDoesNotEnforceIt()
    {
        using var temp = new TempDirectory();
        var (paths, time, status, adapter) = Harness(temp);
        using (adapter)
        {
            var connection = status.ClientConnected();
            var curl = Specs.Block("/usr/bin/curl") with { Enabled = false };
            await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            var generation = PublishedGeneration(paths);
            status.RulesReported(connection, RulesEventWithIds(generation, null), time.GetUtcNow());
            Assert.Equal(RuleState.Applied, Assert.Single(await adapter.ListOwnedRulesAsync(CancellationToken.None)).State);
            var verify = await adapter.VerifyAsync(curl, CancellationToken.None);
            Assert.True(verify.EnforcementVerified);
            Assert.Null(verify.EffectiveAction);
        }
    }

    [Fact]
    public async Task RecoveryRemoval_FilterStillListsTheRule_IsFailedNotVerified()
    {
        using var temp = new TempDirectory();
        using var host = new ServiceHostScope();
        var (paths, time, status, adapter) = Harness(temp);
        using (adapter)
        {
            var connection = status.ClientConnected();
            var curl = Specs.Block("/usr/bin/curl");
            await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            var id = FilterRuleTable.ToFilterRule(curl).Id;
            status.RulesReported(connection, RulesEventWithIds(PublishedGeneration(paths), null, id), time.GetUtcNow());

            // The removal publishes N+1; an ack of N+1 that still lists the rule is not a removal.
            var removalTask = adapter.RemoveCapturedOwnedRuleAsync(curl.ManagedRuleId, FirewallDirection.Outbound, CancellationToken.None);
            var removal = await removalTask;
            Assert.False(removal.Success);
            status.RulesReported(connection, RulesEventWithIds(PublishedGeneration(paths), null, id), time.GetUtcNow());
            var retry = await adapter.RemoveCapturedOwnedRuleAsync(curl.ManagedRuleId, FirewallDirection.Outbound, CancellationToken.None);
            Assert.False(retry.Success);
            Assert.Null(retry.VerifiedUtc);
            Assert.Equal("filter.rule_still_enforced", retry.ErrorCode);
            Assert.NotEqual(OwnedRulePresence.Absent, await adapter.InspectOwnedRuleAsync(curl.ManagedRuleId, FirewallDirection.Outbound, CancellationToken.None));

            // A clean ack without it proves the removal.
            status.RulesReported(connection, RulesEventWithIds(PublishedGeneration(paths), null), time.GetUtcNow());
            var done = await adapter.RemoveCapturedOwnedRuleAsync(curl.ManagedRuleId, FirewallDirection.Outbound, CancellationToken.None);
            Assert.True(done.Success);
            Assert.NotNull(done.VerifiedUtc);
        }
    }
}
