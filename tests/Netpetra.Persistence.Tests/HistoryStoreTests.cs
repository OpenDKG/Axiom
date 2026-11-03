// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.Contracts.Firewall;
using Netpetra.Contracts.History;
using Netpetra.Contracts.Monitoring;
using Netpetra.Persistence;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Netpetra.Persistence.Tests;

public sealed class HistoryStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "netpetra-history-tests",
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
    public async Task Initialize_creates_schema_version_two()
    {
        var store = CreateStore();

        await store.InitializeAsync(CancellationToken.None);

        Assert.True(File.Exists(store.DatabasePath));

        await using var connection = new SqliteConnection($"Data Source={store.DatabasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT MAX(version) FROM schema_migrations;";
        Assert.Equal(2L, Convert.ToInt64(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public async Task Firewall_rule_and_audit_round_trip()
    {
        var store = CreateStore();
        await store.InitializeAsync(CancellationToken.None);

        var id = Guid.NewGuid();
        var rule = new ManagedRule
        {
            ManagedRuleId = id,
            OsRuleName = $"Netpetra::{id:D}::OUT",
            State = RuleState.Applied,
            LastVerifiedUtc = DateTimeOffset.UtcNow,
            Spec = new RuleSpec
            {
                ManagedRuleId = id,
                AppPath = @"C:\Program Files\Example\example.exe",
                Direction = FirewallDirection.Outbound,
                Action = FirewallAction.Block,
                Profiles = FirewallProfile.All,
                CreatedBy = "S-1-5-21-test",
            },
        };

        await store.SaveFirewallRuleAsync(rule, "S-1-5-21-test", "rule.apply", "applied", null);

        var rules = await store.ListFirewallRulesAsync();
        var stored = Assert.Single(rules);
        Assert.Equal(id, stored.ManagedRuleId);
        Assert.Equal(rule.OsRuleName, stored.OsRuleName);
        Assert.Equal(FirewallAction.Block, stored.Spec.Action);
        Assert.Equal(RuleState.Applied, stored.State);

        await store.DeleteFirewallRuleAsync(id, "S-1-5-21-test", "removed", null);
        Assert.Empty(await store.ListFirewallRulesAsync());

        await using var connection = new SqliteConnection($"Data Source={store.DatabasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM rule_audit;";
        Assert.Equal(2L, Convert.ToInt64(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public async Task Upsert_and_query_round_trip_utc_timestamps()
    {
        var store = CreateStore();
        await store.InitializeAsync(CancellationToken.None);

        var captured = new DateTimeOffset(2026, 11, 3, 12, 0, 0, TimeSpan.Zero);
        await store.UpsertAsync(Snapshot(captured, ("chrome.exe", @"C:\chrome.exe", 100, "203.0.113.10:443")));

        var page = await store.QueryAsync(new HistoryQuery
        {
            FromUtc = captured.AddMinutes(-1),
            ToUtc = captured.AddMinutes(1),
        });

        Assert.Equal(1, page.TotalCount);
        var row = Assert.Single(page.Rows);
        Assert.Equal("chrome.exe", row.AppDisplayName);
        Assert.Equal(100, row.ProcessId);
        Assert.Equal("203.0.113.10:443", row.RemoteEndpoint);
        Assert.Equal(captured, row.FirstSeenUtc);
        Assert.Equal(captured, row.LastSeenUtc);
    }

    [Fact]
    public async Task Repeated_upsert_updates_last_seen_without_duplicating()
    {
        var store = CreateStore();
        await store.InitializeAsync(CancellationToken.None);

        var first = new DateTimeOffset(2026, 11, 3, 12, 0, 0, TimeSpan.Zero);
        await store.UpsertAsync(Snapshot(first, ("chrome.exe", @"C:\chrome.exe", 100, "203.0.113.10:443")));
        await store.UpsertAsync(Snapshot(first.AddSeconds(5), ("chrome.exe", @"C:\chrome.exe", 100, "203.0.113.10:443")));

        var page = await store.QueryAsync(new HistoryQuery
        {
            FromUtc = first.AddMinutes(-1),
            ToUtc = first.AddMinutes(1),
        });

        Assert.Equal(1, page.TotalCount);
        Assert.Equal(first, page.Rows[0].FirstSeenUtc);
        Assert.Equal(first.AddSeconds(5), page.Rows[0].LastSeenUtc);
    }

    [Fact]
    public async Task Search_matches_app_path_remote_and_pid()
    {
        var store = CreateStore();
        await store.InitializeAsync(CancellationToken.None);

        var now = DateTimeOffset.UtcNow;
        await store.UpsertAsync(Snapshot(
            now,
            ("chrome.exe", @"C:\Program Files\Chrome\chrome.exe", 100, "203.0.113.10:443"),
            ("codex.exe", @"C:\Tools\codex.exe", 200, "198.51.100.7:443")));

        Assert.Equal(1, (await Query(store, now, "chrome")).TotalCount);
        Assert.Equal(1, (await Query(store, now, "198.51.100")).TotalCount);
        Assert.Equal(1, (await Query(store, now, "200")).TotalCount);
        Assert.Equal(0, (await Query(store, now, "no-such-thing")).TotalCount);
    }

    [Fact]
    public async Task Time_window_and_paging_are_applied()
    {
        var store = CreateStore();
        await store.InitializeAsync(CancellationToken.None);

        var now = DateTimeOffset.UtcNow;
        await store.UpsertAsync(Snapshot(
            now.AddHours(-3),
            ("old.exe", @"C:\old.exe", 1, "203.0.113.1:80")));
        await store.UpsertAsync(Snapshot(
            now,
            ("new.exe", @"C:\new.exe", 2, "203.0.113.2:80")));

        var recent = await store.QueryAsync(new HistoryQuery
        {
            FromUtc = now.AddMinutes(-5),
            ToUtc = now.AddMinutes(1),
        });
        Assert.Equal(1, recent.TotalCount);
        Assert.Equal("new.exe", recent.Rows[0].AppDisplayName);

        var paged = await store.QueryAsync(new HistoryQuery
        {
            FromUtc = now.AddDays(-1),
            ToUtc = now.AddMinutes(1),
            Limit = 1,
            Offset = 1,
        });
        Assert.Equal(2, paged.TotalCount);
        Assert.Single(paged.Rows);
    }

    [Fact]
    public async Task Retention_removes_old_flows_and_orphan_apps()
    {
        var store = CreateStore();
        await store.InitializeAsync(CancellationToken.None);

        var now = DateTimeOffset.UtcNow;
        await store.UpsertAsync(Snapshot(
            now.AddDays(-40),
            ("old.exe", @"C:\old.exe", 1, "203.0.113.1:80")));
        await store.UpsertAsync(Snapshot(
            now,
            ("new.exe", @"C:\new.exe", 2, "203.0.113.2:80")));

        var removed = await store.ApplyRetentionAsync(now, TimeSpan.FromDays(30));

        Assert.Equal(1, removed);

        var page = await store.QueryAsync(new HistoryQuery
        {
            FromUtc = now.AddDays(-60),
            ToUtc = now.AddMinutes(1),
        });

        Assert.Equal(1, page.TotalCount);
        Assert.Equal("new.exe", page.Rows[0].AppDisplayName);
    }

    [Fact]
    public async Task Corrupt_database_is_moved_aside_and_recreated()
    {
        var path = Path.Combine(_directory, "netpetra.db");
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(path, "this is not a sqlite database");

        var store = new HistoryStore(path);
        await store.InitializeAsync(CancellationToken.None);

        Assert.True(File.Exists(path));
        Assert.NotEmpty(Directory.GetFiles(_directory, "netpetra.db.corrupt-*"));

        var page = await store.QueryAsync(new HistoryQuery
        {
            FromUtc = DateTimeOffset.UtcNow.AddHours(-1),
            ToUtc = DateTimeOffset.UtcNow.AddMinutes(1),
        });

        Assert.Equal(0, page.TotalCount);
    }

    private HistoryStore CreateStore() =>
        new(Path.Combine(_directory, "netpetra.db"));

    private static Task<HistoryPage> Query(HistoryStore store, DateTimeOffset now, string search) =>
        store.QueryAsync(new HistoryQuery
        {
            FromUtc = now.AddHours(-1),
            ToUtc = now.AddMinutes(1),
            Search = search,
        });

    private static ConnectionSnapshot Snapshot(
        DateTimeOffset capturedUtc,
        params (string Name, string Path, int Pid, string Remote)[] rows) =>
        new()
        {
            CapturedUtc = capturedUtc,
            SourceName = "test",
            ProcessCount = rows.Select(row => row.Pid).Distinct().Count(),
            Connections = rows.Select(row => new LiveConnection
            {
                AppDisplayName = row.Name,
                AppPath = row.Path,
                ProcessId = row.Pid,
                Protocol = TransportProtocol.Tcp,
                LocalEndpoint = "192.0.2.10:50000",
                RemoteEndpoint = row.Remote,
                State = "Established",
                Direction = ConnectionDirection.Outbound,
                InterfaceName = string.Empty,
                FirstObservedUtc = capturedUtc,
                Quality = DataQuality.Observed,
            }).ToList(),
        };
}
