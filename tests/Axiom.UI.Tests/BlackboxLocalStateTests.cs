// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class BlackboxLocalStateTests
{
    [Fact]
    public void Reads_compiled_rules_and_graph_sample_from_local_state()
    {
        using var temp = new TemporaryDirectory();
        var now = DateTimeOffset.UtcNow;
        File.WriteAllText(
            Path.Combine(temp.Path, "authoritative-sync.json"),
            $$"""
              {
                "status": "partial",
                "phase": "verified-rules-available",
                "public_entries": 450000,
                "community_entries": 0,
                "graph_complete": false,
                "detection_ready": true,
                "updated_at": {{now.ToUnixTimeSeconds()}},
                "started_at": {{now.AddMinutes(-10).ToUnixTimeSeconds()}}
              }
              """);
        File.WriteAllText(
            Path.Combine(temp.Path, "sync_progress.json"),
            """{"counts":[480,450,971]}""");
        File.WriteAllText(
            Path.Combine(temp.Path, "verified_lookup_state.json"),
            """{"state":"ok","reason":""}""");
        File.WriteAllText(
            Path.Combine(temp.Path, "ruleset.json"),
            """
            {
              "graph_threats": [
                {"identifier":"injection:1","name":"Instruction override","category":"injection","severity":"high","source":"public"},
                {"identifier":"ioc:2","name":"Known IOC","category":"ioc","severity":"critical","source":"public"}
              ]
            }
            """);

        var sync = BlackboxLocalState.TryReadSync(temp.Path, now);
        var graph = BlackboxLocalState.TryReadGraph(temp.Path);

        Assert.NotNull(sync);
        Assert.Equal("syncing", sync!.State);
        Assert.Equal(450_000, sync.VerifiedRules);
        Assert.Equal(971, sync.GraphAssets);
        Assert.Equal(480, sync.DownloadedAssets);
        Assert.Equal(450, sync.CompiledAssets);
        Assert.Equal(49.4, sync.PercentDownloaded);
        Assert.Equal(46.3, sync.PercentCompiled);
        Assert.Equal("Live from graph", sync.Lookups.Label);

        Assert.NotNull(graph);
        Assert.Equal(450_000, graph!.Total);
        Assert.Equal(2, graph.Threats.Count);
        Assert.Equal(1, graph.CategoryTotals["injection"]);
        Assert.Equal(1, graph.CategoryTotals["ioc"]);
    }

    [Fact]
    public void Stale_local_state_is_ignored()
    {
        using var temp = new TemporaryDirectory();
        File.WriteAllText(
            Path.Combine(temp.Path, "authoritative-sync.json"),
            """{"status":"partial","public_entries":10,"updated_at":1000}""");

        Assert.Null(BlackboxLocalState.TryReadSync(
            temp.Path,
            DateTimeOffset.UtcNow));
    }

    [Fact]
    public void EvaluateContinuity_preserves_cached_ruleset_offline_and_flags_corruption()
    {
        using var temp = new TemporaryDirectory();
        var syncedAt = new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);
        File.WriteAllText(
            Path.Combine(temp.Path, "verified_lookup_state.json"),
            """{"state":"degraded","reason":"store down"}""");
        File.WriteAllText(
            Path.Combine(temp.Path, "ruleset.json"),
            $$"""
              {
                "synced_at": {{syncedAt.ToUnixTimeSeconds()}},
                "graph_threats": [
                  {"identifier":"injection:1","name":"Prompt override","category":"injection","severity":"high","source":"public"}
                ],
                "verified_scope": {
                  "verified_counts": {
                    "dependency": 252860,
                    "ioc": 856005
                  }
                }
              }
              """);

        var report = BlackboxLocalState.EvaluateContinuity(
            temp.Path,
            guardPresent: true,
            dkgConnected: false,
            now: syncedAt.AddHours(8));

        Assert.True(report.GuardAvailable);
        Assert.True(report.RulesetAvailable);
        Assert.True(report.SyncStale);
        Assert.True(report.DkgOffline);
        Assert.False(report.IsUnprotected);

        var sync = BlackboxLocalState.TryReadSync(temp.Path, syncedAt.AddHours(8));
        Assert.NotNull(sync);
        Assert.Equal("synced", sync!.State);
        Assert.Equal(1_108_866, sync.VerifiedRules);

        File.WriteAllText(Path.Combine(temp.Path, "ruleset.json"), "{corrupt");
        var corrupted = BlackboxLocalState.EvaluateContinuity(temp.Path, guardPresent: true);
        Assert.True(corrupted.RulesetCorrupted);
        Assert.True(corrupted.IsUnprotected);
    }

    [Fact]
    public void Streaming_parser_caches_unchanged_ruleset_and_rejects_non_object_roots()
    {
        using var temp = new TemporaryDirectory();
        var rulesetPath = Path.Combine(temp.Path, "ruleset.json");
        var syncedAt = new DateTimeOffset(2026, 11, 16, 10, 0, 0, TimeSpan.Zero);
        var invariant = System.Globalization.CultureInfo.InvariantCulture;

        var sb = new System.Text.StringBuilder();
        sb.Append(invariant, $"{{\"synced_at\":{syncedAt.ToUnixTimeSeconds()},\"graph_threats\":[");
        for (var i = 0; i < 600; i++)
        {
            if (i > 0)
            {
                sb.Append(',');
            }

            sb.Append(invariant, $"{{\"identifier\":\"ioc:{i}\",\"name\":\"Threat {i} padding payload to cross 64KB chunk boundary\",\"category\":\"ioc\",\"severity\":\"high\",\"source\":\"public\"}}");
        }

        sb.Append("]}");
        File.WriteAllText(rulesetPath, sb.ToString());

        var report = BlackboxLocalState.EvaluateContinuity(temp.Path, guardPresent: true, dkgConnected: true, now: syncedAt.AddMinutes(1));
        var sync = BlackboxLocalState.TryReadSync(temp.Path, syncedAt.AddMinutes(1));
        var graph = BlackboxLocalState.TryReadGraph(temp.Path);

        Assert.True(report.RulesetAvailable);
        Assert.Equal(600, report.CompiledRuleCount);
        Assert.NotNull(sync);
        Assert.NotNull(graph);
        Assert.True(graph!.Threats.Count <= 256);
        Assert.Equal(1, BlackboxLocalState.GetParseCountForPathForTests(rulesetPath));

        File.WriteAllText(rulesetPath, "[1,2,3]");
        var nonObject = BlackboxLocalState.EvaluateContinuity(temp.Path, guardPresent: true);
        Assert.True(nonObject.RulesetCorrupted);
        Assert.Equal(2, BlackboxLocalState.GetParseCountForPathForTests(rulesetPath));
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "axiom-blackbox-state-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }
}
