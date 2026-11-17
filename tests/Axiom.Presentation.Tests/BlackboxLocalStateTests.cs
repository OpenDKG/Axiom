// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class BlackboxLocalStateTests
{
    [Fact]
    public void EvaluateContinuity_before_sync_reports_guard_available_and_unprotected()
    {
        using var temp = new TemporaryDirectory();

        var report = BlackboxLocalState.EvaluateContinuity(
            root: temp.Path,
            guardPresent: true,
            dkgConnected: true,
            now: DateTimeOffset.UtcNow);

        Assert.True(report.GuardAvailable);
        Assert.False(report.RulesetAvailable);
        Assert.False(report.SyncStale);
        Assert.False(report.DkgOffline);
        Assert.True(report.IsUnprotected);
        Assert.Contains("GUARD_AVAILABLE", report.StateTokens);
        Assert.Contains("UNPROTECTED", report.StateTokens);
        Assert.DoesNotContain("RULESET_AVAILABLE", report.StateTokens);
        Assert.Null(BlackboxLocalState.TryReadSync(temp.Path));
    }

    [Fact]
    public void EvaluateContinuity_and_TryReadSync_preserve_cached_ruleset_beyond_ten_minutes()
    {
        using var temp = new TemporaryDirectory();
        var syncedAt = new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);
        WriteHealthyState(temp.Path, syncedAt, lookupState: "ok");

        // 45 minutes later (within 6h staleness window, past old 10m AuthoritativeFreshness)
        var offlineNow = syncedAt.AddMinutes(45);
        var report = BlackboxLocalState.EvaluateContinuity(
            root: temp.Path,
            guardPresent: true,
            dkgConnected: true,
            now: offlineNow);

        Assert.True(report.GuardAvailable);
        Assert.True(report.RulesetAvailable);
        Assert.False(report.SyncStale);
        Assert.False(report.DkgOffline);
        Assert.False(report.IsUnprotected);
        Assert.Equal(2, report.CompiledRuleCount);
        Assert.Equal(1_108_865, report.LiveScopeRuleCount);
        Assert.Contains("GUARD_AVAILABLE", report.StateTokens);
        Assert.Contains("RULESET_AVAILABLE", report.StateTokens);
        Assert.DoesNotContain("UNPROTECTED", report.StateTokens);

        var sync = BlackboxLocalState.TryReadSync(temp.Path, offlineNow);
        Assert.NotNull(sync);
        Assert.Equal("synced", sync!.State);
        Assert.Equal(1_109_000, sync.VerifiedRules);
    }

    [Fact]
    public void Offline_more_than_six_hours_marks_sync_stale_without_dropping_cached_rules()
    {
        using var temp = new TemporaryDirectory();
        var syncedAt = new DateTimeOffset(2026, 11, 14, 1, 0, 0, TimeSpan.Zero);
        WriteHealthyState(temp.Path, syncedAt, lookupState: "degraded");

        var later = syncedAt.AddHours(8);
        var report = BlackboxLocalState.EvaluateContinuity(
            root: temp.Path,
            guardPresent: true,
            dkgConnected: false,
            now: later);

        Assert.True(report.GuardAvailable);
        Assert.True(report.RulesetAvailable);
        Assert.True(report.SyncStale);
        Assert.True(report.DkgOffline);
        Assert.False(report.IsUnprotected);
        Assert.Contains("GUARD_AVAILABLE", report.StateTokens);
        Assert.Contains("RULESET_AVAILABLE", report.StateTokens);
        Assert.Contains("SYNC_STALE", report.StateTokens);
        Assert.Contains("DKG_OFFLINE", report.StateTokens);

        var sync = BlackboxLocalState.TryReadSync(temp.Path, later);
        Assert.NotNull(sync);
        Assert.Equal("synced", sync!.State);
        Assert.Contains("older than 6 hours", sync.PhaseText, StringComparison.OrdinalIgnoreCase);

        var annotator = DkgContextAnnotator.LoadFromLocalCache(temp.Path, now: later);
        var hit = annotator.Annotate("c2.verified.example", now: later);
        Assert.Equal(DkgContextTier.Verified, hit.Tier);
        Assert.True(hit.IsStaleCache);
    }

    [Fact]
    public void Offline_reboot_without_authoritative_sync_recovers_full_ruleset_and_verified_counts()
    {
        using var temp = new TemporaryDirectory();
        var syncedAt = new DateTimeOffset(2026, 11, 14, 10, 0, 0, TimeSpan.Zero);
        WriteHealthyState(temp.Path, syncedAt, lookupState: "degraded");
        File.Delete(Path.Combine(temp.Path, "authoritative-sync.json"));

        var sync = BlackboxLocalState.TryReadSync(temp.Path, syncedAt.AddHours(2));
        var graph = BlackboxLocalState.TryReadGraph(temp.Path);

        Assert.NotNull(sync);
        Assert.Equal("synced", sync!.State);
        Assert.Equal(1_108_867, sync.VerifiedRules);

        Assert.NotNull(graph);
        Assert.Equal(1_108_867, graph!.Total);
        Assert.Equal(252_860, graph.CategoryTotals["dependency"]);
        Assert.Equal(856_005, graph.CategoryTotals["ioc"]);
    }

    [Fact]
    public void Corrupted_or_missing_ruleset_never_falsely_reports_synced_even_when_sync_file_is_fresh()
    {
        using var temp = new TemporaryDirectory();
        var now = new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);
        File.WriteAllText(
            Path.Combine(temp.Path, "authoritative-sync.json"),
            $$"""{"status":"done","public_entries":1109000,"updated_at":{{now.ToUnixTimeSeconds()}}}""");
        File.WriteAllText(Path.Combine(temp.Path, "ruleset.json"), "{corrupted json");

        var report = BlackboxLocalState.EvaluateContinuity(
            root: temp.Path,
            guardPresent: true,
            dkgConnected: false,
            now: now);

        Assert.True(report.RulesetCorrupted);
        Assert.False(report.RulesetAvailable);
        Assert.True(report.IsUnprotected);
        Assert.Contains("UNPROTECTED", report.StateTokens);

        var sync = BlackboxLocalState.TryReadSync(temp.Path, now);
        Assert.NotNull(sync);
        Assert.Equal("unavailable", sync!.State);
        Assert.Equal(0, sync.VerifiedRules);
    }

    [Fact]
    public void Stale_curator_manifest_and_refused_kill_list_are_surfaced_honestly()
    {
        using var temp = new TemporaryDirectory();
        var syncedAt = new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);
        File.WriteAllText(
            Path.Combine(temp.Path, "ruleset.json"),
            $$"""
              {
                "synced_at": {{syncedAt.ToUnixTimeSeconds()}},
                "curator_manifest_state": "STALE since 2026-11-10T00:00:00Z",
                "kill_list_refused": "invalid signature on kill-list manifest",
                "graph_threats": [
                  {"identifier":"injection:1","name":"Prompt override","category":"injection","severity":"high","source":"public"}
                ]
              }
              """);

        var report = BlackboxLocalState.EvaluateContinuity(
            root: temp.Path,
            guardPresent: true,
            dkgConnected: true,
            now: syncedAt.AddMinutes(5));

        Assert.True(report.RulesetAvailable);
        Assert.True(report.CuratorManifestStale);
        Assert.True(report.KillListRefused);
        Assert.Contains("Kill-list", report.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Curator", report.Summary, StringComparison.OrdinalIgnoreCase);

        var sync = BlackboxLocalState.TryReadSync(temp.Path, syncedAt.AddMinutes(5));
        Assert.NotNull(sync);
        Assert.Contains("Kill-list", sync!.PhaseText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Curator manifest is stale", sync.PhaseText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Streaming_parser_handles_multi_chunk_bom_ruleset_and_caches_until_file_changes()
    {
        using var temp = new TemporaryDirectory();
        var syncedAt = new DateTimeOffset(2026, 11, 16, 10, 0, 0, TimeSpan.Zero);
        var unix = syncedAt.ToUnixTimeSeconds();
        var rulesetPath = Path.Combine(temp.Path, "ruleset.json");
        var invariant = System.Globalization.CultureInfo.InvariantCulture;

        var sb = new System.Text.StringBuilder();
        sb.Append(invariant, $"{{\"synced_at\":{unix},\"graph_threats\":[");
        for (var i = 0; i < 1200; i++)
        {
            if (i > 0)
            {
                sb.Append(',');
            }

            sb.Append(invariant, $"{{\"identifier\":\"ioc:{i}\",\"name\":\"Indicator {i} with padding payload to span multiple 64KB chunks\",\"category\":\"ioc\",\"severity\":\"high\",\"source\":\"public\",\"meta\":{{\"identifier\":\"ignored-nested-{i}\"}}}}");
        }

        sb.Append("],\"dependency\":{");
        for (var i = 0; i < 200; i++)
        {
            if (i > 0)
            {
                sb.Append(',');
            }

            sb.Append(invariant, $"\"pkg-{i}\":{{\"bad\":true}}");
        }

        sb.Append(invariant, $"}},\"verified_scope\":{{\"built_at\":{unix},\"verified_counts\":{{\"ioc\":5000,\"dependency:npm\":999}}}}}}");

        File.WriteAllText(rulesetPath, sb.ToString(), new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

        Assert.True(BlackboxLocalState.HasVerifiedRulesFile(rulesetPath));
        var report = BlackboxLocalState.EvaluateContinuity(temp.Path, guardPresent: true, dkgConnected: true, now: syncedAt.AddMinutes(5));
        var sync = BlackboxLocalState.TryReadSync(temp.Path, syncedAt.AddMinutes(5));
        var graph = BlackboxLocalState.TryReadGraph(temp.Path);

        Assert.True(report.RulesetAvailable);
        Assert.Equal(1400, report.CompiledRuleCount);
        Assert.Equal(5000, report.LiveScopeRuleCount);
        Assert.NotNull(sync);
        Assert.Equal(6400, sync!.VerifiedRules);
        Assert.NotNull(graph);
        Assert.True(graph!.Threats.Count <= 256 + 12);
        Assert.DoesNotContain(graph.Threats, t => t.Identifier.StartsWith("ignored-nested-", StringComparison.Ordinal));
        Assert.Equal(200, graph.CategoryTotals["dependency"]);
        Assert.Equal(5000, graph.CategoryTotals["ioc"]);
        Assert.Equal(1, BlackboxLocalState.GetParseCountForPathForTests(rulesetPath));

        // Changing the file invalidates the cache immediately.
        File.WriteAllText(rulesetPath, """{"graph_threats":[]}""", new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        var afterChange = BlackboxLocalState.EvaluateContinuity(temp.Path, guardPresent: true, dkgConnected: true, now: syncedAt.AddMinutes(5));
        Assert.False(afterChange.RulesetAvailable);
        Assert.False(BlackboxLocalState.HasVerifiedRulesFile(rulesetPath));
        Assert.Equal(2, BlackboxLocalState.GetParseCountForPathForTests(rulesetPath));
    }

    private static void WriteHealthyState(string root, DateTimeOffset syncedAt, string lookupState)
    {
        var unix = syncedAt.ToUnixTimeSeconds();
        File.WriteAllText(
            Path.Combine(root, "authoritative-sync.json"),
            $$"""
              {
                "status": "done",
                "phase": "complete",
                "public_entries": 1109000,
                "updated_at": {{unix}},
                "started_at": {{unix - 60}}
              }
              """);
        File.WriteAllText(
            Path.Combine(root, "verified_lookup_state.json"),
            $$"""{"state":"{{lookupState}}","reason":"test lookup state"}""");
        File.WriteAllText(
            Path.Combine(root, "ruleset.json"),
            $$"""
              {
                "synced_at": {{unix}},
                "curator_manifest_state": "",
                "kill_list_refused": "",
                "graph_threats": [
                  {"identifier":"injection:1","name":"Instruction override","category":"injection","severity":"high","source":"public"},
                  {"identifier":"c2.verified.example","name":"Verified C2","category":"ioc","severity":"critical","source":"public"}
                ],
                "injection": [
                  {"identifier":"injection:1","name":"Instruction override","category":"injection","severity":"high","source":"public"}
                ],
                "skill": [],
                "verified_scope": {
                  "built_at": {{unix}},
                  "verified_counts": {
                    "dependency": 252860,
                    "ioc": 856005,
                    "dependency:npm": 235218
                  }
                }
              }
              """);
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "axiom-pres-blackbox-" + Guid.NewGuid().ToString("N"));
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
