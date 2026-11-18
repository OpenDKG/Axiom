// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Protection;
using Axiom.Core.Protection;
using Axiom.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Axiom.Service.Tests;

/// <summary>
/// An allow decision ("Unblock") is only recorded when the block rule it replaces was removed.
/// A failed removal used to be reported as an error while the decision was still saved as
/// Allow, so the remembered decisions said "Allowed" with the block rule still in force.
/// </summary>
public sealed class ProtectionDecideUnblockTests : IDisposable
{
    private const string Actor = "S-1-5-21-test";

    // Native path per OS: Windows-style rule paths are rejected off Windows (#441).
    private static readonly string AppPath = OperatingSystem.IsWindows()
        ? @"C:\Program Files\Example\example.exe"
        : "/usr/lib/example/example";

    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "axiom-decide-tests",
        Guid.NewGuid().ToString("N"));

    private readonly FakeFirewallPolicyAdapter _adapter = new();

    private readonly HistoryStore _history;

    private readonly FirewallRuleCoordinator _coordinator;

    private readonly ProtectionSettingsStore _settings;

    private readonly ProtectionController _controller;

    public ProtectionDecideUnblockTests()
    {
        Directory.CreateDirectory(_directory);
        _history = new HistoryStore(Path.Combine(_directory, "axiom.db"));
        _history.InitializeAsync(CancellationToken.None).GetAwaiter().GetResult();
        _coordinator = new FirewallRuleCoordinator(_adapter, _history, NullLogger<FirewallRuleCoordinator>.Instance);
        _settings = new ProtectionSettingsStore(Path.Combine(_directory, "protection.json"));
        _controller = new ProtectionController(
            _settings,
            new ConnectionSnapshotCache(),
            _coordinator,
            NullLogger<ProtectionController>.Instance);
    }

    public void Dispose()
    {
        _coordinator.Dispose();
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public async Task Allow_is_not_recorded_when_the_block_rule_could_not_be_removed()
    {
        Assert.True(_settings.Save(new ProtectionSettings { Enabled = true }));
        await Decide(ProtectionDecisionAction.Block);
        Assert.Single(_adapter.Rules);

        _adapter.FailNextRemove = true;
        var status = await Decide(ProtectionDecisionAction.Allow);

        Assert.NotNull(status.LastError);
        Assert.Contains("Could not remove", status.LastError, StringComparison.Ordinal);
        var decision = Assert.Single(_settings.Load().Decisions ?? []);
        Assert.Equal(ProtectionDecisionAction.Block, decision.Action);
    }

    [Fact]
    public async Task Allow_is_recorded_once_the_block_rule_is_removed()
    {
        Assert.True(_settings.Save(new ProtectionSettings { Enabled = true }));
        await Decide(ProtectionDecisionAction.Block);

        var status = await Decide(ProtectionDecisionAction.Allow);

        Assert.Null(status.LastError);
        Assert.Empty(_adapter.Rules);
        var decision = Assert.Single(_settings.Load().Decisions ?? []);
        Assert.Equal(ProtectionDecisionAction.Allow, decision.Action);
    }

    private Task<ProtectionStatus> Decide(ProtectionDecisionAction action) =>
        _controller.DecideAsync(
            new ProtectionDecideRequest { AppPath = AppPath, AppName = "example", Action = action },
            Actor,
            CancellationToken.None);
}
