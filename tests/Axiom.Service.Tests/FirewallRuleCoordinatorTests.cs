// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class FirewallRuleCoordinatorTests : IDisposable
{
    private const string Actor = "S-1-5-21-test";

    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "axiom-coordinator-tests",
        Guid.NewGuid().ToString("N"));

    private readonly FakeFirewallPolicyAdapter _adapter = new();

    private readonly HistoryStore _store;

    private readonly FirewallRuleCoordinator _coordinator;

    public FirewallRuleCoordinatorTests()
    {
        _store = new HistoryStore(Path.Combine(_directory, "axiom.db"));
        _store.InitializeAsync(CancellationToken.None).GetAwaiter().GetResult();
        _coordinator = new FirewallRuleCoordinator(
            _adapter,
            _store,
            NullLogger<FirewallRuleCoordinator>.Instance);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    /// <summary>
    /// Review 2026-11-12 (P0 #2): an adapter that only published the rule (macOS: filter
    /// acknowledgement outstanding) answers Pending; the store and audit must not say "applied".
    /// </summary>
    [Fact]
    public async Task Apply_pending_is_stored_as_pending_not_applied()
    {
        var spec = NewSpec();
        _adapter.UpsertOverride = id => new RuleApplyResult
        {
            Success = true,
            ManagedRuleId = id,
            State = RuleState.Pending,
            ErrorMessage = "awaiting AxiomFilter acknowledgement of generation 7",
        };

        var result = await _coordinator.ApplyAsync(spec, Actor, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(RuleState.Pending, result.State);
        var stored = Assert.Single(await _store.ListFirewallRulesAsync());
        Assert.Equal(RuleState.Pending, stored.State);
        Assert.Null(stored.LastVerifiedUtc);
    }

    [Fact]
    public async Task Apply_success_stores_applied_state_and_audit()
    {
        var spec = NewSpec();

        var result = await _coordinator.ApplyAsync(spec, Actor, CancellationToken.None);

        Assert.True(result.Success);
        var stored = Assert.Single(await _store.ListFirewallRulesAsync());
        Assert.Equal(RuleState.Applied, stored.State);
        Assert.Equal(spec.ManagedRuleId, stored.ManagedRuleId);
        Assert.Equal(2, await CountAuditAsync(spec.ManagedRuleId));
        Assert.Equal(1, _adapter.UpsertCalls);
    }

    [Fact]
    public async Task Apply_failure_stores_failed_state_and_error()
    {
        var spec = NewSpec();
        _adapter.FailNextApply = true;

        var result = await _coordinator.ApplyAsync(spec, Actor, CancellationToken.None);

        Assert.False(result.Success);
        var stored = Assert.Single(await _store.ListFirewallRulesAsync());
        Assert.Equal(RuleState.Failed, stored.State);
        Assert.Equal("fake.apply_failed", stored.LastErrorCode);
        Assert.Equal(2, await CountAuditAsync(spec.ManagedRuleId));
    }

    [Fact]
    public async Task Invalid_spec_is_rejected_without_calling_the_adapter()
    {
        var spec = NewSpec() with { AppPath = string.Empty };

        var result = await _coordinator.ApplyAsync(spec, Actor, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("rule.invalid", result.ErrorCode);
        Assert.Equal(0, _adapter.UpsertCalls);
        Assert.Empty(await _store.ListFirewallRulesAsync());
    }

    [Fact]
    public async Task Remove_deletes_the_stored_rule_and_audits()
    {
        var spec = NewSpec();
        await _coordinator.ApplyAsync(spec, Actor, CancellationToken.None);

        var result = await _coordinator.RemoveAsync(spec.ManagedRuleId, Actor, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Empty(await _store.ListFirewallRulesAsync());
        Assert.Equal(3, await CountAuditAsync(spec.ManagedRuleId));
    }

    [Fact]
    public async Task Remove_failure_is_audited_and_marks_the_stored_rule_failed()
    {
        var spec = NewSpec();
        await _coordinator.ApplyAsync(spec, Actor, CancellationToken.None);
        _adapter.FailNextRemove = true;

        var result = await _coordinator.RemoveAsync(spec.ManagedRuleId, Actor, CancellationToken.None);

        Assert.False(result.Success);
        var stored = Assert.Single(await _store.ListFirewallRulesAsync());
        Assert.Equal(RuleState.Failed, stored.State);
        Assert.Equal("fake.remove_failed", stored.LastErrorCode);
        Assert.Equal(1, await CountAuditResultAsync(spec.ManagedRuleId, "rule.remove", "failed"));
    }

    [Fact]
    public async Task Remove_adapter_exception_is_audited_and_returned_as_failure()
    {
        var spec = NewSpec();
        await _coordinator.ApplyAsync(spec, Actor, CancellationToken.None);
        _adapter.ThrowOnRemove = true;

        var result = await _coordinator.RemoveAsync(spec.ManagedRuleId, Actor, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("rule.remove_exception", result.ErrorCode);
        var stored = Assert.Single(await _store.ListFirewallRulesAsync());
        Assert.Equal(RuleState.Failed, stored.State);
        Assert.Equal(1, await CountAuditResultAsync(spec.ManagedRuleId, "rule.remove", "failed"));
    }

    [Fact]
    public async Task Verify_reads_the_fake_adapter_state()
    {
        var spec = NewSpec();
        await _coordinator.ApplyAsync(spec, Actor, CancellationToken.None);

        var report = await _coordinator.VerifyAsync(spec.ManagedRuleId, CancellationToken.None);

        Assert.True(report.PresentInOs);
        Assert.True(report.MatchesSpec);
        Assert.Equal(FirewallAction.Block, report.EffectiveAction);
    }

    [Fact]
    public async Task Apply_cancellation_marks_rule_failed_instead_of_leaving_pending()
    {
        var spec = NewSpec();
        using var cts = new CancellationTokenSource();
        _adapter.UpsertOverride = _ =>
        {
            cts.Cancel();
            cts.Token.ThrowIfCancellationRequested();
            throw new InvalidOperationException("unreachable");
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _coordinator.ApplyAsync(spec, Actor, cts.Token));

        var stored = Assert.Single(await _store.ListFirewallRulesAsync());
        Assert.Equal(RuleState.Failed, stored.State);
        Assert.Equal("rule.apply_canceled", stored.LastErrorCode);
    }

    private static RuleSpec NewSpec() => new()
    {
        ManagedRuleId = Guid.NewGuid(),
        // Native path per OS: Windows-style rule paths are rejected off Windows (#441).
        AppPath = OperatingSystem.IsWindows() ? @"C:\Program Files\Example\example.exe" : "/usr/lib/example/example",
        Direction = FirewallDirection.Outbound,
        Action = FirewallAction.Block,
        Profiles = FirewallProfile.All,
        CreatedBy = Actor,
    };

    private async Task<int> CountAuditAsync(Guid id)
    {
        await using var connection = new SqliteConnection($"Data Source={_store.DatabasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM rule_audit WHERE managed_rule_id = $id;";
        command.Parameters.AddWithValue("$id", id.ToString("D"));
        return Convert.ToInt32(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private async Task<int> CountAuditResultAsync(Guid id, string action, string result)
    {
        await using var connection = new SqliteConnection($"Data Source={_store.DatabasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*) FROM rule_audit
            WHERE managed_rule_id = $id AND action = $action AND result = $result;
            """;
        command.Parameters.AddWithValue("$id", id.ToString("D"));
        command.Parameters.AddWithValue("$action", action);
        command.Parameters.AddWithValue("$result", result);
        return Convert.ToInt32(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
    }
}
