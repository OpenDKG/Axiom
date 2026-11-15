// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiom.Contracts.Blackbox;

namespace Axiom.Presentation;

/// <summary>
/// Distinct continuity dimensions for Axiom + Agent Blackbox offline operation:
/// guard runtime availability, local cached ruleset availability, sync staleness,
/// live DKG store reachability, and missing/corrupted ruleset state.
/// </summary>
public sealed record BlackboxContinuityReport(
    bool GuardAvailable,
    bool RulesetAvailable,
    bool SyncStale,
    bool DkgOffline,
    bool IsUnprotected,
    bool RulesetCorrupted,
    bool CuratorManifestStale,
    bool KillListRefused,
    int CompiledRuleCount,
    int LiveScopeRuleCount,
    DateTimeOffset? LastSyncedUtc,
    IReadOnlyList<string> StateTokens,
    string Summary);

/// <summary>
/// Reads the state files the local Blackbox sync writes beside its dashboard and evaluates
/// offline continuity independently of dashboard availability or fresh DKG connectivity.
/// </summary>
public static class BlackboxLocalState
{
    private static readonly TimeSpan AuthoritativeFreshness = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan StaleSyncThreshold = TimeSpan.FromHours(6);

    public static BlackboxContinuityReport EvaluateContinuity(
        string? root = null,
        bool? guardPresent = null,
        bool? dkgConnected = null,
        DateTimeOffset? now = null)
    {
        var guardAvailable = guardPresent ?? IsLocalGuardRuntimeInstalled();
        var home = ResolveHome(root);
        if (home is null)
        {
            return BuildReport(
                guardAvailable,
                rulesetAvailable: false,
                syncStale: false,
                dkgOffline: dkgConnected == false,
                rulesetCorrupted: false,
                curatorManifestStale: false,
                killListRefused: false,
                compiledRuleCount: 0,
                liveScopeRuleCount: 0,
                lastSyncedUtc: null,
                missingRuleset: true);
        }

        var ruleset = InspectRuleset(Path.Combine(home, "ruleset.json"));
        var authoritative = ReadObject(Path.Combine(home, "authoritative-sync.json"));
        var lookup = ReadObject(Path.Combine(home, "verified_lookup_state.json"));
        var lookupState = ReadString(lookup, "state") ?? string.Empty;
        var lookupDegraded = IsLookupDegraded(lookupState);

        var lastSyncedUtc = LatestTimestamp(
            ruleset.SyncedUtc,
            ReadUnixSeconds(authoritative, "updated_at"));
        var referenceNow = now ?? DateTimeOffset.UtcNow;
        var rulesetAvailable = ruleset.State == RulesetParseState.Valid &&
                               (ruleset.CompiledRules > 0 || ruleset.LiveScopeRules > 0);
        var syncStale = rulesetAvailable &&
                        lastSyncedUtc is { } syncedAt &&
                        (referenceNow - syncedAt) > StaleSyncThreshold;
        var dkgOffline = dkgConnected == false || (dkgConnected is null && lookupDegraded) || lookupDegraded;

        return BuildReport(
            guardAvailable,
            rulesetAvailable,
            syncStale,
            dkgOffline,
            rulesetCorrupted: ruleset.State == RulesetParseState.Corrupted,
            curatorManifestStale: ruleset.CuratorManifestStale,
            killListRefused: ruleset.KillListRefused,
            compiledRuleCount: ruleset.CompiledRules,
            liveScopeRuleCount: ruleset.LiveScopeRules,
            lastSyncedUtc: lastSyncedUtc,
            missingRuleset: ruleset.State == RulesetParseState.Missing || !rulesetAvailable);
    }

    public static BlackboxVerifiedSync? TryReadSync(string? root = null, DateTimeOffset? now = null)
    {
        var home = ResolveHome(root);
        if (home is null)
        {
            return null;
        }

        var authoritative = ReadObject(Path.Combine(home, "authoritative-sync.json"));
        var ruleset = InspectRuleset(Path.Combine(home, "ruleset.json"));
        var referenceNow = now ?? DateTimeOffset.UtcNow;

        if (ruleset.State == RulesetParseState.Corrupted)
        {
            return BuildUnavailableSync(
                authoritative,
                phaseText: "The local ruleset cache is corrupted; online synchronization is required.",
                home: home);
        }

        var rulesetAvailable = ruleset.State == RulesetParseState.Valid &&
                               (ruleset.CompiledRules > 0 || ruleset.LiveScopeRules > 0);
        if (!rulesetAvailable)
        {
            if (authoritative is null)
            {
                return null;
            }

            var authStatus = ReadString(authoritative, "status") ?? string.Empty;
            var authUpdated = ReadUnixSeconds(authoritative, "updated_at");
            if (IsCompletedStatus(authStatus))
            {
                return BuildUnavailableSync(
                    authoritative,
                    phaseText: "Local ruleset cache is missing or empty; online synchronization is required.",
                    home: home);
            }

            if (authUpdated is { } staleTs && (referenceNow - staleTs) > AuthoritativeFreshness)
            {
                return null;
            }
        }

        var authUpdatedAt = ReadUnixSeconds(authoritative, "updated_at");
        var updated = authUpdatedAt ?? ruleset.SyncedUtc;
        var authoritativeFresh = authoritative is not null &&
                                 authUpdatedAt is { } ts &&
                                 (referenceNow - ts) <= AuthoritativeFreshness;

        var progress = ReadObject(Path.Combine(home, "sync_progress.json"));
        var counts = progress?["counts"] as JsonArray;
        var downloaded = ReadInt(counts, 0);
        var compiled = ReadInt(counts, 1);
        var total = ReadInt(counts, 2);
        var publicEntries = ReadInt(authoritative, "public_entries");
        var verifiedRules = publicEntries > 0
            ? publicEntries
            : rulesetAvailable
                ? ruleset.TotalRules
                : compiled;
        var status = ReadString(authoritative, "status") ?? string.Empty;
        var error = ReadString(authoritative, "error") ?? string.Empty;
        var hasRules = verifiedRules > 0;

        string state;
        if (authoritativeFresh)
        {
            state = status.ToLowerInvariant() switch
            {
                "done" or "complete" or "completed" or "synced" => "synced",
                "failed" or "cancelled" when !hasRules => "unavailable",
                _ when hasRules => "syncing",
                _ => "unknown",
            };
        }
        else if (rulesetAvailable)
        {
            state = "synced";
        }
        else
        {
            state = status.ToLowerInvariant() switch
            {
                "failed" or "cancelled" => "unavailable",
                _ => "unknown",
            };
        }

        var lookup = ReadObject(Path.Combine(home, "verified_lookup_state.json"));
        var lookupState = ReadString(lookup, "state") ?? "unknown";
        var lookupLabel = string.Equals(lookupState, "ok", StringComparison.OrdinalIgnoreCase)
            ? "Live from graph"
            : "Node not answering";
        var lookupText = ReadString(lookup, "reason") ?? string.Empty;

        var isSyncStale = rulesetAvailable &&
                          LatestTimestamp(ruleset.SyncedUtc, authUpdatedAt) is { } syncedAt &&
                          (referenceNow - syncedAt) > StaleSyncThreshold;

        var phaseText = state switch
        {
            "synced" => FormatSyncedPhaseText(
                verifiedRules,
                isSyncStale,
                IsLookupDegraded(lookupState),
                ruleset.CuratorManifestStale,
                ruleset.KillListRefused),
            "syncing" when hasRules => $"{verifiedRules:N0} verified rules are loaded; graph catch-up continues.",
            "unavailable" => string.IsNullOrWhiteSpace(error)
                ? "The local DKG node is not answering."
                : error,
            _ => string.IsNullOrWhiteSpace(error)
                ? "Waiting for the local verified graph."
                : error,
        };

        return new BlackboxVerifiedSync(
            state,
            total > 0 ? total : null,
            downloaded > 0 ? downloaded : null,
            null,
            compiled > 0 ? compiled : null,
            verifiedRules,
            total > 0 ? Percent(downloaded, total) : null,
            total > 0 ? Percent(compiled, total) : null,
            updated?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? string.Empty,
            new BlackboxLookupState(lookupState, lookupLabel, lookupText),
            ReadString(authoritative, "phase") ?? (rulesetAvailable ? "cached-ruleset" : string.Empty),
            phaseText,
            ReadUnixSeconds(authoritative, "started_at"),
            ReadString(progress, "last_change") ?? string.Empty);
    }

    public static BlackboxGraphPage? TryReadGraph(string? root = null)
    {
        var home = ResolveHome(root);
        if (home is null)
        {
            return null;
        }

        var ruleset = ReadObject(Path.Combine(home, "ruleset.json"));
        if (ruleset is null)
        {
            return null;
        }

        var entries = new Dictionary<string, BlackboxGraphThreat>(StringComparer.OrdinalIgnoreCase);
        var categoryTotals = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (ruleset["graph_threats"] is JsonArray graphThreats)
        {
            AddThreats(entries, graphThreats, "other");
            categoryTotals["other"] = entries.Values.Count(threat => threat.Category == "other");
        }

        foreach (var category in new[] { "injection", "escalation", "dependency", "fileaccess", "skill", "ioc", "secret" })
        {
            var node = ruleset[category];
            if (node is JsonArray array)
            {
                categoryTotals[category] = array.Count;
                AddThreats(entries, array, category);
            }
            else if (node is JsonObject map)
            {
                categoryTotals[category] = map.Count;
                foreach (var property in map.Take(12))
                {
                    entries.TryAdd(property.Key, new BlackboxGraphThreat(
                        property.Key,
                        property.Key,
                        category,
                        category is "ioc" or "dependency" ? "high" : "info",
                        string.Empty,
                        "public"));
                }
            }
        }

        var liveScopeCount = 0;
        if (ruleset["verified_scope"] is JsonObject verifiedScope &&
            verifiedScope["verified_counts"] is JsonObject verifiedCounts)
        {
            foreach (var property in verifiedCounts)
            {
                if (property.Key.Contains(':', StringComparison.Ordinal))
                {
                    continue;
                }

                if (property.Value is JsonValue val && val.TryGetValue<int>(out var count) && count > 0)
                {
                    liveScopeCount += count;
                    categoryTotals[property.Key] = categoryTotals.TryGetValue(property.Key, out var existing)
                        ? Math.Max(existing, count)
                        : count;
                }
            }
        }

        if (entries.Count == 0 && liveScopeCount == 0)
        {
            return null;
        }

        foreach (var group in entries.Values.GroupBy(threat => threat.Category, StringComparer.OrdinalIgnoreCase))
        {
            categoryTotals.TryAdd(group.Key, group.Count());
        }

        var authoritative = ReadObject(Path.Combine(home, "authoritative-sync.json"));
        var publicEntries = ReadInt(authoritative, "public_entries");
        var inspected = InspectRulesetObject(ruleset);
        var total = publicEntries > 0 ? publicEntries : Math.Max(inspected.TotalRules, entries.Count);
        return new BlackboxGraphPage(entries.Values.ToList(), total, Partial: true)
        {
            CategoryTotals = categoryTotals,
        };
    }

    private static bool IsLocalGuardRuntimeInstalled()
    {
        try
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(local))
            {
                return false;
            }

            var root = Path.Combine(local, "Axiom", "modules", "blackbox", "agent-blackbox");
            var python = Path.Combine(root, "venv", "Scripts", "python.exe");
            var hooks = Path.Combine(root, "plugins", "blackbox", "guard", "hooks.py");
            return File.Exists(python) && File.Exists(hooks);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static BlackboxContinuityReport BuildReport(
        bool guardAvailable,
        bool rulesetAvailable,
        bool syncStale,
        bool dkgOffline,
        bool rulesetCorrupted,
        bool curatorManifestStale,
        bool killListRefused,
        int compiledRuleCount,
        int liveScopeRuleCount,
        DateTimeOffset? lastSyncedUtc,
        bool missingRuleset)
    {
        var isUnprotected = !guardAvailable || !rulesetAvailable;
        var tokens = new List<string>(5);
        if (guardAvailable)
        {
            tokens.Add("GUARD_AVAILABLE");
        }

        if (rulesetAvailable)
        {
            tokens.Add("RULESET_AVAILABLE");
        }

        if (syncStale)
        {
            tokens.Add("SYNC_STALE");
        }

        if (dkgOffline)
        {
            tokens.Add("DKG_OFFLINE");
        }

        if (isUnprotected)
        {
            tokens.Add("UNPROTECTED");
        }

        string summary;
        if (!guardAvailable)
        {
            summary = "Blackbox guard runtime is not installed; local agent hooks are unprotected.";
        }
        else if (rulesetCorrupted)
        {
            summary = "Local ruleset cache is corrupted; only built-in zero-graph rules apply until resynchronization.";
        }
        else if (missingRuleset)
        {
            summary = "Local ruleset cache is missing or empty; online synchronization is required.";
        }
        else if (dkgOffline)
        {
            summary = syncStale
                ? $"DKG node is offline and cached rules are stale ({compiledRuleCount:N0} compiled local rules active; {liveScopeRuleCount:N0} live-lookup rules require DKG or index fallback)."
                : $"DKG node is offline; cached local rules remain active ({compiledRuleCount:N0} compiled rules active; {liveScopeRuleCount:N0} live-lookup rules depend on DKG unless index fallback is enabled).";
        }
        else if (syncStale)
        {
            summary = $"Cached ruleset is active offline ({compiledRuleCount + liveScopeRuleCount:N0} rules), but synchronization is stale.";
        }
        else
        {
            summary = $"Guard and verified ruleset are available ({compiledRuleCount + liveScopeRuleCount:N0} rules).";
        }

        if (killListRefused)
        {
            summary += " Kill-list update refused; retaining last known-good policy.";
        }

        if (curatorManifestStale)
        {
            summary += " Curator trust manifest is stale.";
        }

        return new BlackboxContinuityReport(
            guardAvailable,
            rulesetAvailable,
            syncStale,
            dkgOffline,
            isUnprotected,
            rulesetCorrupted,
            curatorManifestStale,
            killListRefused,
            compiledRuleCount,
            liveScopeRuleCount,
            lastSyncedUtc,
            tokens,
            summary);
    }

    private static BlackboxVerifiedSync BuildUnavailableSync(
        JsonObject? authoritative,
        string phaseText,
        string home)
    {
        var updated = ReadUnixSeconds(authoritative, "updated_at");
        var lookup = ReadObject(Path.Combine(home, "verified_lookup_state.json"));
        var lookupState = ReadString(lookup, "state") ?? "unknown";
        var lookupLabel = string.Equals(lookupState, "ok", StringComparison.OrdinalIgnoreCase)
            ? "Live from graph"
            : "Node not answering";
        var lookupText = ReadString(lookup, "reason") ?? string.Empty;

        return new BlackboxVerifiedSync(
            "unavailable",
            null,
            null,
            null,
            null,
            0,
            null,
            null,
            updated?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? string.Empty,
            new BlackboxLookupState(lookupState, lookupLabel, lookupText),
            ReadString(authoritative, "phase") ?? string.Empty,
            phaseText,
            ReadUnixSeconds(authoritative, "started_at"),
            string.Empty);
    }

    private static string FormatSyncedPhaseText(
        int verifiedRules,
        bool isSyncStale,
        bool isLookupDegraded,
        bool curatorManifestStale,
        bool killListRefused)
    {
        var baseText = isSyncStale
            ? $"{verifiedRules:N0} verified rules cached offline (sync is older than 6 hours)."
            : $"{verifiedRules:N0} verified rules are available.";

        if (isLookupDegraded)
        {
            baseText += " Live DKG lookups are offline; cached local rules remain active.";
        }

        if (killListRefused)
        {
            baseText += " Kill-list update was refused; last known-good policy kept.";
        }

        if (curatorManifestStale)
        {
            baseText += " Curator manifest is stale.";
        }

        return baseText;
    }

    private static bool IsCompletedStatus(string status) =>
        status.Trim().ToLowerInvariant() is "done" or "complete" or "completed" or "synced";

    private static bool IsLookupDegraded(string lookupState) =>
        lookupState.Trim().ToLowerInvariant() is "degraded" or "error" or "offline" or "unavailable";

    private static DateTimeOffset? LatestTimestamp(DateTimeOffset? first, DateTimeOffset? second) =>
        first is null ? second : second is null ? first : first > second ? first : second;

    private enum RulesetParseState
    {
        Missing = 0,
        Corrupted = 1,
        Valid = 2,
    }

    private sealed record RulesetInspection(
        RulesetParseState State,
        int CompiledRules,
        int LiveScopeRules,
        int TotalRules,
        DateTimeOffset? SyncedUtc,
        bool CuratorManifestStale,
        bool KillListRefused);

    private static RulesetInspection InspectRuleset(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return new RulesetInspection(RulesetParseState.Missing, 0, 0, 0, null, false, false);
            }

            if (JsonNode.Parse(File.ReadAllText(path)) is not JsonObject root)
            {
                return new RulesetInspection(RulesetParseState.Corrupted, 0, 0, 0, null, false, false);
            }

            return InspectRulesetObject(root);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new RulesetInspection(RulesetParseState.Corrupted, 0, 0, 0, null, false, false);
        }
    }

    private static RulesetInspection InspectRulesetObject(JsonObject root)
    {
        var graphThreats = CountNode(root["graph_threats"]);
        var smallTierSum = CountNode(root["injection"]) +
                           CountNode(root["escalation"]) +
                           CountNode(root["fileaccess"]) +
                           CountNode(root["skill"]);
        var compiledRules = Math.Max(graphThreats, smallTierSum) +
                            CountNode(root["dependency"]) +
                            CountNode(root["ioc"]) +
                            CountNode(root["secret"]) +
                            CountNode(root["community"]);

        var liveScopeRules = 0;
        DateTimeOffset? builtAt = null;
        if (root["verified_scope"] is JsonObject verifiedScope)
        {
            builtAt = ReadUnixSeconds(verifiedScope, "built_at");
            if (verifiedScope["verified_counts"] is JsonObject verifiedCounts)
            {
                foreach (var property in verifiedCounts)
                {
                    if (!property.Key.Contains(':', StringComparison.Ordinal) &&
                        property.Value is JsonValue val &&
                        val.TryGetValue<int>(out var count) &&
                        count > 0)
                    {
                        liveScopeRules += count;
                    }
                }
            }
        }

        var syncedUtc = ReadUnixSeconds(root, "synced_at") ?? builtAt;
        var manifestState = ReadString(root, "curator_manifest_state") ?? string.Empty;
        var curatorManifestStale = manifestState.StartsWith("STALE", StringComparison.OrdinalIgnoreCase);

        var killListRefused = false;
        if (root["kill_list_refused"] is JsonValue killVal)
        {
            if (killVal.TryGetValue<bool>(out var boolFlag))
            {
                killListRefused = boolFlag;
            }
            else if (killVal.TryGetValue<string>(out var reasonText))
            {
                killListRefused = !string.IsNullOrWhiteSpace(reasonText);
            }
        }

        return new RulesetInspection(
            RulesetParseState.Valid,
            compiledRules,
            liveScopeRules,
            compiledRules + liveScopeRules,
            syncedUtc,
            curatorManifestStale,
            killListRefused);
    }

    private static int CountNode(JsonNode? node) => node switch
    {
        JsonArray array => array.Count,
        JsonObject obj => obj.Count,
        _ => 0,
    };

    private static void AddThreats(
        Dictionary<string, BlackboxGraphThreat> entries,
        JsonArray items,
        string fallbackCategory)
    {
        foreach (var item in items.OfType<JsonObject>())
        {
            var identifier = ReadString(item, "identifier");
            if (string.IsNullOrWhiteSpace(identifier))
            {
                continue;
            }

            entries.TryAdd(identifier, new BlackboxGraphThreat(
                identifier,
                ReadString(item, "name") ?? string.Empty,
                ReadString(item, "category") ?? fallbackCategory,
                ReadString(item, "severity") ?? "info",
                string.Empty,
                ReadString(item, "source") ?? "public"));
        }
    }

    private static string? ResolveHome(string? root)
    {
        if (!string.IsNullOrWhiteSpace(root))
        {
            return Directory.Exists(root) ? root : null;
        }

        var candidates = new[]
        {
            BlackboxPaths.ResolveBlackboxHome(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".hermes", "blackbox"),
        };

        return candidates.FirstOrDefault(Directory.Exists);
    }

    private static JsonObject? ReadObject(string path)
    {
        try
        {
            return File.Exists(path)
                ? JsonNode.Parse(File.ReadAllText(path)) as JsonObject
                : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    private static string? ReadString(JsonObject? value, string property) =>
        value?[property] is JsonValue node && node.TryGetValue<string>(out var text) ? text : null;

    private static int ReadInt(JsonObject? value, string property) =>
        value?[property] is JsonValue node && node.TryGetValue<int>(out var number) ? number : 0;

    private static int ReadInt(JsonArray? values, int index) =>
        values is not null && index < values.Count &&
        values[index] is JsonValue node && node.TryGetValue<int>(out var number)
            ? number
            : 0;

    private static DateTimeOffset? ReadUnixSeconds(JsonObject? value, string property)
    {
        if (value?[property] is not JsonValue node || !node.TryGetValue<double>(out var seconds) ||
            !double.IsFinite(seconds) || seconds <= 0)
        {
            return null;
        }

        return DateTimeOffset.FromUnixTimeMilliseconds((long)(seconds * 1000));
    }

    private static double Percent(int value, int total) =>
        total <= 0 ? 0 : Math.Round(value * 100d / total, 1);
}
