// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.History;
using Axiom.Contracts.Monitoring;
using Axiom.Persistence;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Axiom.Persistence.Tests;

public sealed class HistoryStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "axiom-history-tests",
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
    public async Task Initialize_creates_schema_version_three()
    {
        var store = CreateStore();

        await store.InitializeAsync(CancellationToken.None);

        Assert.True(File.Exists(store.DatabasePath));

        await using var connection = new SqliteConnection($"Data Source={store.DatabasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT MAX(version) FROM schema_migrations;";
        Assert.Equal(3L, Convert.ToInt64(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture));
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
            OsRuleName = $"Axiom::{id:D}::OUT",
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
    public async Task Throughput_history_aggregates_minutes_and_keeps_unmeasured_gaps()
    {
        var store = CreateStore();
        await store.InitializeAsync(CancellationToken.None);

        var start = DateTimeOffset.FromUnixTimeSeconds(
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60 * 60);

        await store.RecordThroughputAsync(start, 600, 1_200, 60);
        await store.RecordThroughputAsync(start.AddMinutes(1), 300, 600, 30);

        // The sampler owns the minute; a later write replaces the earlier partial value.
        await store.RecordThroughputAsync(start.AddMinutes(1), 400, 800, 40);

        var history = await store.QueryThroughputAsync(new ThroughputHistoryQuery
        {
            FromUtc = start,
            ToUtc = start.AddMinutes(3),
            BucketSeconds = 60,
        });

        Assert.Equal(60, history.BucketSeconds);
        Assert.Equal(4, history.Points.Count);
        Assert.Equal(600, history.Points[0].UploadBytes);
        Assert.Equal(1_200, history.Points[0].DownloadBytes);
        Assert.Equal(60, history.Points[0].MeasuredSeconds);
        Assert.Equal(400, history.Points[1].UploadBytes);
        Assert.Equal(40, history.Points[1].MeasuredSeconds);

        // A minute without a measurement stays explicit instead of looking like zero traffic.
        Assert.Equal(0, history.Points[2].MeasuredSeconds);
        Assert.Equal(0, history.Points[2].UploadBytes);
        Assert.NotNull(history.Detail);

        await store.RecordThroughputAsync(start.AddMinutes(4), 100, 200, 60);

        var fiveMinute = await store.QueryThroughputAsync(new ThroughputHistoryQuery
        {
            FromUtc = start,
            ToUtc = start.AddMinutes(4),
            BucketSeconds = 300,
        });

        Assert.Equal(1_100, fiveMinute.Points.Sum(point => point.UploadBytes));
        Assert.Equal(2_200, fiveMinute.Points.Sum(point => point.DownloadBytes));
        Assert.Equal(160, fiveMinute.Points.Sum(point => point.MeasuredSeconds));
    }

    [Fact]
    public async Task Retention_removes_old_throughput_buckets()
    {
        var store = CreateStore();
        await store.InitializeAsync(CancellationToken.None);

        var now = DateTimeOffset.UtcNow;
        await store.RecordThroughputAsync(now.AddDays(-40), 1_000, 2_000, 60);
        await store.RecordThroughputAsync(now, 500, 700, 60);

        await store.ApplyRetentionAsync(now, TimeSpan.FromDays(30));

        var history = await store.QueryThroughputAsync(new ThroughputHistoryQuery
        {
            FromUtc = now.AddDays(-40).AddMinutes(-5),
            ToUtc = now.AddMinutes(1),
            BucketSeconds = 3_600,
        });

        var totalUpload = history.Points.Sum(point => point.UploadBytes);
        Assert.Equal(500, totalUpload);
    }

    [Fact]
    public async Task Corrupt_database_is_moved_aside_and_recreated()
    {
        var path = Path.Combine(_directory, "axiom.db");
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(path, "this is not a sqlite database");

        var store = new HistoryStore(path);
        await store.InitializeAsync(CancellationToken.None);

        Assert.True(File.Exists(path));
        Assert.NotEmpty(Directory.GetFiles(_directory, "axiom.db.corrupt-*"));

        var page = await store.QueryAsync(new HistoryQuery
        {
            FromUtc = DateTimeOffset.UtcNow.AddHours(-1),
            ToUtc = DateTimeOffset.UtcNow.AddMinutes(1),
        });

        Assert.Equal(0, page.TotalCount);
    }

    [Fact]
    public async Task Baseline_aggregates_without_transferring_every_row()
    {
        var store = CreateStore();
        await store.InitializeAsync(CancellationToken.None);

        var now = DateTimeOffset.UtcNow;
        await store.UpsertAsync(Snapshot(
            now,
            ("chrome.exe", @"C:\Program Files\Chrome\chrome.exe", 100, "203.0.113.10:443"),
            ("chrome.exe", @"C:\Program Files\Chrome\chrome.exe", 100, "203.0.113.11:443"),
            ("codex.exe", @"C:\Tools\codex.exe", 200, "198.51.100.7:443")));

        var page = await store.QueryAsync(new HistoryQuery
        {
            FromUtc = now.AddMinutes(-1),
            ToUtc = now.AddMinutes(1),
            Limit = 1,
            IncludeBaseline = true,
        });

        var baseline = Assert.IsType<HistoryBaseline>(page.Baseline);
        Assert.Equal(3, baseline.TotalFlows);
        Assert.Equal(2, baseline.Apps.Count);
        Assert.Single(page.Rows);

        var chrome = baseline.Apps.Single(app => app.DisplayName == "chrome.exe");
        Assert.Equal(2, chrome.FlowRows);
        Assert.Equal(2, chrome.TypicalRemotes.Count);
        Assert.Equal(
            2,
            baseline.Flows.Count(flow =>
                flow.AppKey.EndsWith("chrome.exe", StringComparison.OrdinalIgnoreCase)));
    }

    private HistoryStore CreateStore() =>
        new(Path.Combine(_directory, "axiom.db"));

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
