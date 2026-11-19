// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Protection;
using Axiom.Core.Protection;
using Axiom.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class ProtectionControllerTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "axiom-protection-tests",
        Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public async Task Concurrent_decisions_and_status_polls_do_not_lose_persisted_decisions()
    {
        Directory.CreateDirectory(_directory);
        var settingsPath = Path.Combine(_directory, "protection.json");
        var settingsStore = new ProtectionSettingsStore(settingsPath);
        Assert.True(settingsStore.Save(new ProtectionSettings
        {
            Enabled = true,
            DefaultPolicy = "ask",
        }));

        var history = new HistoryStore(Path.Combine(_directory, "axiom.db"));
        await history.InitializeAsync(CancellationToken.None);
        var cache = new ConnectionSnapshotCache();
        cache.Update(new ConnectionSnapshot
        {
            CapturedUtc = DateTimeOffset.UtcNow,
            SourceName = "test",
            ProcessCount = 1,
            Connections =
            [
                new LiveConnection
                {
                    AppDisplayName = "agent.exe",
                    AppPath = @"C:\Agents\agent.exe",
                    ProcessId = 4242,
                    Protocol = TransportProtocol.Tcp,
                    LocalEndpoint = "192.0.2.10:50000",
                    RemoteEndpoint = "203.0.113.50:443",
                    State = "Established",
                    Direction = ConnectionDirection.Outbound,
                    InterfaceName = string.Empty,
                    FirstObservedUtc = DateTimeOffset.UtcNow,
                    Quality = DataQuality.Observed,
                },
            ],
        });

        using var coordinator = new FirewallRuleCoordinator(
            new FakeFirewallPolicyAdapter(),
            history,
            NullLogger<FirewallRuleCoordinator>.Instance);
        using var controller = new ProtectionController(
            settingsStore,
            cache,
            coordinator,
            NullLogger<ProtectionController>.Instance);

        var paths = Enumerable.Range(1, 6)
            .Select(index => $@"C:\Apps\app{index}.exe")
            .ToArray();

        var tasks = paths.Select(path =>
            controller.DecideAsync(
                new ProtectionDecideRequest
                {
                    AppPath = path,
                    AppName = Path.GetFileName(path),
                    Action = ProtectionDecisionAction.Allow,
                },
                "S-1-5-21-test",
                CancellationToken.None))
            .Concat(
            [
                controller.GetStatusAsync(null, CancellationToken.None),
                controller.GetStatusAsync(null, CancellationToken.None),
            ]);

        await Task.WhenAll(tasks);

        var finalStatus = await controller.GetStatusAsync(null, CancellationToken.None);
        Assert.Equal(paths.Length, finalStatus.Decisions.Count);
        foreach (var path in paths)
        {
            Assert.Contains(
                finalStatus.Decisions,
                decision => string.Equals(decision.AppPath, path, StringComparison.OrdinalIgnoreCase));
        }
    }
}
