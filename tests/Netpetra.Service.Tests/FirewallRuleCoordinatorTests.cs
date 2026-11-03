// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.Contracts.Firewall;
using Netpetra.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Netpetra.Service.Tests;

public sealed class FirewallRuleCoordinatorTests : IDisposable
{
    private const string Actor = "S-1-5-21-test";

    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "netpetra-coordinator-tests",
        Guid.NewGuid().ToString("N"));

    private readonly FakeFirewallPolicyAdapter _adapter = new();

    private readonly HistoryStore _store;

    private readonly FirewallRuleCoordinator _coordinator;

    public FirewallRuleCoordinatorTests()
    {
        _store = new HistoryStore(Path.Combine(_directory, "netpetra.db"));
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
    public async Task Verify_reads_the_fake_adapter_state()
    {
        var spec = NewSpec();
        await _coordinator.ApplyAsync(spec, Actor, CancellationToken.None);

        var report = await _coordinator.VerifyAsync(spec.ManagedRuleId, CancellationToken.None);

        Assert.True(report.PresentInOs);
        Assert.True(report.MatchesSpec);
        Assert.Equal(FirewallAction.Block, report.EffectiveAction);
    }

    private static RuleSpec NewSpec() => new()
    {
        ManagedRuleId = Guid.NewGuid(),
        AppPath = @"C:\Program Files\Example\example.exe",
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
}
