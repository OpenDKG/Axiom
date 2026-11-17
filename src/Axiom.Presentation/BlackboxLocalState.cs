// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers;
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
    private static readonly string[] GraphCategories = ["injection", "escalation", "dependency", "fileaccess", "skill", "ioc", "secret"];
    private const int MaxGraphThreatsSample = 256;
    private const int MaxCategoryArraySample = 80;
    private const int MaxCategoryMapSample = 12;
    private const int MaxCachedRulesets = 8;
    private const int StreamBufferInitialSize = 64 * 1024;

    private static readonly object RulesetCacheGate = new();
    private static readonly Dictionary<string, CachedRulesetEntry> RulesetCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, int> RulesetParseCountsByPath = new(StringComparer.OrdinalIgnoreCase);

    internal static int GetParseCountForPathForTests(string path)
    {
        lock (RulesetCacheGate)
        {
            return RulesetParseCountsByPath.GetValueOrDefault(path);
        }
    }

    internal static void ClearCacheForTests()
    {
        lock (RulesetCacheGate)
        {
            RulesetCache.Clear();
            RulesetParseCountsByPath.Clear();
        }
    }

    internal static bool HasVerifiedRulesFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var snapshot = GetOrParseRulesetSnapshot(path);
        return snapshot.Inspection.State == RulesetParseState.Valid && snapshot.HasVerifiedRules;
    }

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

        var snapshot = GetOrParseRulesetSnapshot(Path.Combine(home, "ruleset.json"));
        if (snapshot.Inspection.State != RulesetParseState.Valid)
        {
            return null;
        }

        var entries = new Dictionary<string, BlackboxGraphThreat>(StringComparer.OrdinalIgnoreCase);
        var categoryTotals = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (snapshot.HasGraphThreatsArray)
        {
            foreach (var threat in snapshot.GraphThreatsSamples)
            {
                entries.TryAdd(threat.Identifier, threat);
            }

            categoryTotals["other"] = snapshot.GraphThreatsSamples.Count < snapshot.CollectionCounts.GetValueOrDefault("graph_threats")
                ? snapshot.GraphThreatsCategoryCounts.GetValueOrDefault("other")
                : entries.Values.Count(threat => threat.Category == "other");
        }

        foreach (var category in GraphCategories)
        {
            if (snapshot.ArrayCategorySamples.TryGetValue(category, out var arraySamples))
            {
                categoryTotals[category] = snapshot.CollectionCounts.GetValueOrDefault(category);
                foreach (var threat in arraySamples)
                {
                    entries.TryAdd(threat.Identifier, threat);
                }
            }
            else if (snapshot.MapCategorySamples.TryGetValue(category, out var mapKeys))
            {
                categoryTotals[category] = snapshot.CollectionCounts.GetValueOrDefault(category);
                foreach (var key in mapKeys)
                {
                    entries.TryAdd(key, new BlackboxGraphThreat(
                        key,
                        key,
                        category,
                        category is "ioc" or "dependency" ? "high" : "info",
                        string.Empty,
                        "public"));
                }
            }
        }

        var liveScopeCount = 0;
        foreach (var (key, count) in snapshot.VerifiedCounts)
        {
            liveScopeCount += count;
            categoryTotals[key] = categoryTotals.TryGetValue(key, out var existing)
                ? Math.Max(existing, count)
                : count;
        }

        if (entries.Count == 0 && liveScopeCount == 0)
        {
            return null;
        }

        foreach (var group in entries.Values.GroupBy(threat => threat.Category, StringComparer.OrdinalIgnoreCase))
        {
            categoryTotals.TryAdd(group.Key, group.Count());
        }

        if (snapshot.HasGraphThreatsArray)
        {
            foreach (var (cat, cnt) in snapshot.GraphThreatsCategoryCounts)
            {
                if (categoryTotals.TryGetValue(cat, out var existing))
                {
                    if (snapshot.CollectionCounts.GetValueOrDefault("graph_threats") > MaxGraphThreatsSample)
                    {
                        categoryTotals[cat] = Math.Max(existing, cnt);
                    }
                }
                else
                {
                    categoryTotals.TryAdd(cat, cnt);
                }
            }
        }

        var authoritative = ReadObject(Path.Combine(home, "authoritative-sync.json"));
        var publicEntries = ReadInt(authoritative, "public_entries");
        var total = publicEntries > 0 ? publicEntries : Math.Max(snapshot.Inspection.TotalRules, entries.Count);
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

            return IsGuardRuntimeInstalledAt(
                Path.Combine(local, "Axiom", "modules", "blackbox", "agent-blackbox"));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Whether the Blackbox guard runtime (venv interpreter + guard hooks) exists under
    /// <paramref name="blackboxRoot"/> (<c>.../Axiom/modules/blackbox/agent-blackbox</c>).
    /// </summary>
    public static bool IsGuardRuntimeInstalledAt(string blackboxRoot)
    {
        // Windows: venv\Scripts\python.exe (as upstream); macOS/Linux: venv/bin/python.
        var python = AgentPlatform.VenvPython(blackboxRoot);
        var hooks = Path.Combine(blackboxRoot, "plugins", "blackbox", "guard", "hooks.py");
        return File.Exists(python) && File.Exists(hooks);
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

    private readonly record struct RulesetFingerprint(long Length, long LastWriteTimeUtcTicks);

    private sealed record CachedRulesetEntry(
        RulesetFingerprint Fingerprint,
        RulesetSnapshot Snapshot);

    private sealed record RulesetSnapshot(
        RulesetInspection Inspection,
        bool HasVerifiedRules,
        bool HasGraphThreatsArray,
        IReadOnlyList<BlackboxGraphThreat> GraphThreatsSamples,
        IReadOnlyDictionary<string, int> GraphThreatsCategoryCounts,
        IReadOnlyDictionary<string, int> CollectionCounts,
        IReadOnlyDictionary<string, IReadOnlyList<BlackboxGraphThreat>> ArrayCategorySamples,
        IReadOnlyDictionary<string, IReadOnlyList<string>> MapCategorySamples,
        IReadOnlyDictionary<string, int> VerifiedCounts)
    {
        public static readonly RulesetSnapshot Missing = new(
            new RulesetInspection(RulesetParseState.Missing, 0, 0, 0, null, false, false),
            HasVerifiedRules: false,
            HasGraphThreatsArray: false,
            GraphThreatsSamples: Array.Empty<BlackboxGraphThreat>(),
            GraphThreatsCategoryCounts: new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase),
            CollectionCounts: new Dictionary<string, int>(StringComparer.Ordinal),
            ArrayCategorySamples: new Dictionary<string, IReadOnlyList<BlackboxGraphThreat>>(StringComparer.Ordinal),
            MapCategorySamples: new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal),
            VerifiedCounts: new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase));

        public static readonly RulesetSnapshot Corrupted = new(
            new RulesetInspection(RulesetParseState.Corrupted, 0, 0, 0, null, false, false),
            HasVerifiedRules: false,
            HasGraphThreatsArray: false,
            GraphThreatsSamples: Array.Empty<BlackboxGraphThreat>(),
            GraphThreatsCategoryCounts: new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase),
            CollectionCounts: new Dictionary<string, int>(StringComparer.Ordinal),
            ArrayCategorySamples: new Dictionary<string, IReadOnlyList<BlackboxGraphThreat>>(StringComparer.Ordinal),
            MapCategorySamples: new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal),
            VerifiedCounts: new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase));
    }

    private enum RootSection
    {
        None = 0,
        CountedCollection = 1,
        VerifiedScope = 2,
    }

    private sealed class RulesetStreamAccumulator
    {
        private readonly Dictionary<string, int> _collectionCounts = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> _graphThreatsCategoryCounts = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<BlackboxGraphThreat> _graphThreatsSamples = new();
        private readonly Dictionary<string, List<BlackboxGraphThreat>> _arrayCategorySamples = new(StringComparer.Ordinal);
        private readonly Dictionary<string, List<string>> _mapCategorySamples = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> _verifiedCounts = new(StringComparer.OrdinalIgnoreCase);

        private bool _sawRootStart;
        private bool _sawRootEnd;
        private bool _invalidRoot;

        private string? _currentRootProp;
        private bool _expectingRootValue;
        private RootSection _section;

        private bool _collectionIsArray;
        private bool _collectionIsObject;
        private int _collectionCount;

        private bool _inThreatItem;
        private string? _threatProp;
        private string? _threatId;
        private string? _threatName;
        private string? _threatCategory;
        private string? _threatSeverity;
        private string? _threatSource;

        private string? _scopeProp;
        private bool _inVerifiedCounts;
        private string? _verifiedCountKey;
        private bool _hasVerifiedScopeCountProperty;

        private bool _hasGraphThreatsArray;
        private bool _hasNonEmptyVerifiedArray;
        private DateTimeOffset? _builtAt;
        private DateTimeOffset? _syncedAt;
        private bool _curatorManifestStale;
        private bool _killListRefused;

        public bool Invalid => _invalidRoot;

        public void ProcessToken(ref Utf8JsonReader reader)
        {
            if (_invalidRoot)
            {
                return;
            }

            if (_sawRootEnd)
            {
                _invalidRoot = true;
                return;
            }

            if (!_sawRootStart)
            {
                if (reader.TokenType != JsonTokenType.StartObject)
                {
                    _invalidRoot = true;
                    return;
                }

                _sawRootStart = true;
                return;
            }

            if (reader.TokenType == JsonTokenType.EndObject && reader.CurrentDepth == 0)
            {
                _sawRootEnd = true;
                return;
            }

            if (reader.CurrentDepth == 1)
            {
                ProcessDepthOne(ref reader);
                return;
            }

            if (_section == RootSection.CountedCollection)
            {
                ProcessCollectionToken(ref reader);
            }
            else if (_section == RootSection.VerifiedScope)
            {
                ProcessVerifiedScopeToken(ref reader);
            }
        }

        public RulesetSnapshot BuildSnapshot()
        {
            if (!_sawRootStart || !_sawRootEnd || _invalidRoot)
            {
                return RulesetSnapshot.Corrupted;
            }

            var graphThreats = _collectionCounts.GetValueOrDefault("graph_threats");
            var smallTierSum = _collectionCounts.GetValueOrDefault("injection") +
                               _collectionCounts.GetValueOrDefault("escalation") +
                               _collectionCounts.GetValueOrDefault("fileaccess") +
                               _collectionCounts.GetValueOrDefault("skill");
            var compiledRules = Math.Max(graphThreats, smallTierSum) +
                                _collectionCounts.GetValueOrDefault("dependency") +
                                _collectionCounts.GetValueOrDefault("ioc") +
                                _collectionCounts.GetValueOrDefault("secret") +
                                _collectionCounts.GetValueOrDefault("community");

            var liveScopeRules = 0;
            foreach (var count in _verifiedCounts.Values)
            {
                liveScopeRules += count;
            }

            var syncedUtc = _syncedAt ?? _builtAt;
            var inspection = new RulesetInspection(
                RulesetParseState.Valid,
                compiledRules,
                liveScopeRules,
                compiledRules + liveScopeRules,
                syncedUtc,
                _curatorManifestStale,
                _killListRefused);

            var arraySamplesReadOnly = _arrayCategorySamples.ToDictionary(
                pair => pair.Key,
                pair => (IReadOnlyList<BlackboxGraphThreat>)pair.Value,
                StringComparer.Ordinal);
            var mapSamplesReadOnly = _mapCategorySamples.ToDictionary(
                pair => pair.Key,
                pair => (IReadOnlyList<string>)pair.Value,
                StringComparer.Ordinal);

            return new RulesetSnapshot(
                inspection,
                _hasNonEmptyVerifiedArray || _hasVerifiedScopeCountProperty,
                _hasGraphThreatsArray,
                _graphThreatsSamples,
                _graphThreatsCategoryCounts,
                _collectionCounts,
                arraySamplesReadOnly,
                mapSamplesReadOnly,
                _verifiedCounts);
        }

        private void ProcessDepthOne(ref Utf8JsonReader reader)
        {
            if (reader.TokenType == JsonTokenType.PropertyName)
            {
                _currentRootProp = reader.GetString();
                _expectingRootValue = true;
                _section = RootSection.None;
                return;
            }

            if (_section != RootSection.None &&
                (reader.TokenType == JsonTokenType.EndArray || reader.TokenType == JsonTokenType.EndObject))
            {
                FinalizeRootSection();
                return;
            }

            if (!_expectingRootValue)
            {
                return;
            }

            _expectingRootValue = false;
            var prop = _currentRootProp;
            if (prop is null)
            {
                return;
            }

            if (prop == "synced_at")
            {
                _syncedAt = TryReadUnixSeconds(ref reader);
                return;
            }

            if (prop == "curator_manifest_state")
            {
                var manifestState = reader.TokenType == JsonTokenType.String
                    ? reader.GetString() ?? string.Empty
                    : string.Empty;
                _curatorManifestStale = manifestState.StartsWith("STALE", StringComparison.OrdinalIgnoreCase);
                return;
            }

            if (prop == "kill_list_refused")
            {
                _killListRefused = reader.TokenType switch
                {
                    JsonTokenType.True => true,
                    JsonTokenType.String => !string.IsNullOrWhiteSpace(reader.GetString()),
                    _ => false,
                };
                return;
            }

            if (IsCountedCollectionKey(prop) &&
                (reader.TokenType == JsonTokenType.StartArray || reader.TokenType == JsonTokenType.StartObject))
            {
                _section = RootSection.CountedCollection;
                _collectionIsArray = reader.TokenType == JsonTokenType.StartArray;
                _collectionIsObject = reader.TokenType == JsonTokenType.StartObject;
                _collectionCount = 0;
                _inThreatItem = false;
                if (_collectionIsArray)
                {
                    if (prop == "graph_threats")
                    {
                        _hasGraphThreatsArray = true;
                        _graphThreatsSamples.Clear();
                        _graphThreatsCategoryCounts.Clear();
                    }
                    else if (IsGraphCategoryKey(prop))
                    {
                        _arrayCategorySamples[prop] = new List<BlackboxGraphThreat>();
                        _mapCategorySamples.Remove(prop);
                    }
                }
                else if (prop == "graph_threats")
                {
                    _hasGraphThreatsArray = false;
                    _graphThreatsSamples.Clear();
                    _graphThreatsCategoryCounts.Clear();
                }
                else if (IsGraphCategoryKey(prop))
                {
                    _mapCategorySamples[prop] = new List<string>();
                    _arrayCategorySamples.Remove(prop);
                }

                return;
            }

            if (prop == "verified_scope" && reader.TokenType == JsonTokenType.StartObject)
            {
                _section = RootSection.VerifiedScope;
                _scopeProp = null;
                _inVerifiedCounts = false;
                _verifiedCountKey = null;
                _builtAt = null;
                _verifiedCounts.Clear();
                _hasVerifiedScopeCountProperty = false;
            }
        }

        private void FinalizeRootSection()
        {
            if (_section == RootSection.CountedCollection &&
                _currentRootProp is not null &&
                (_collectionIsArray || _collectionIsObject))
            {
                _collectionCounts[_currentRootProp] = _collectionCount;
                if (_collectionIsArray && _collectionCount > 0 && IsVerifiedArrayKey(_currentRootProp))
                {
                    _hasNonEmptyVerifiedArray = true;
                }
            }

            _section = RootSection.None;
            _currentRootProp = null;
            _expectingRootValue = false;
            _collectionIsArray = false;
            _collectionIsObject = false;
            _collectionCount = 0;
            _inThreatItem = false;
            _inVerifiedCounts = false;
            _scopeProp = null;
            _verifiedCountKey = null;
        }

        private void ProcessCollectionToken(ref Utf8JsonReader reader)
        {
            var prop = _currentRootProp;
            if (prop is null)
            {
                return;
            }

            if (_collectionIsObject)
            {
                if (reader.CurrentDepth == 2 && reader.TokenType == JsonTokenType.PropertyName)
                {
                    _collectionCount++;
                    if (IsGraphCategoryKey(prop) &&
                        _mapCategorySamples.TryGetValue(prop, out var keys) &&
                        keys.Count < MaxCategoryMapSample)
                    {
                        keys.Add(reader.GetString() ?? string.Empty);
                    }
                }

                return;
            }

            if (!_collectionIsArray)
            {
                return;
            }

            if (reader.CurrentDepth == 2)
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    if (_inThreatItem)
                    {
                        FinalizeThreatItem(prop);
                    }

                    return;
                }

                if (reader.TokenType != JsonTokenType.EndArray)
                {
                    _collectionCount++;
                    if (reader.TokenType == JsonTokenType.StartObject &&
                        (prop == "graph_threats" || IsGraphCategoryKey(prop)))
                    {
                        _inThreatItem = true;
                        _threatProp = null;
                        _threatId = null;
                        _threatName = null;
                        _threatCategory = null;
                        _threatSeverity = null;
                        _threatSource = null;
                    }
                }

                return;
            }

            if (reader.CurrentDepth == 3 && _inThreatItem)
            {
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    _threatProp = reader.GetString();
                }
                else if (_threatProp is not null)
                {
                    var text = reader.TokenType == JsonTokenType.String ? reader.GetString() : null;
                    switch (_threatProp)
                    {
                        case "identifier":
                            _threatId = text;
                            break;
                        case "name":
                            _threatName = text;
                            break;
                        case "category":
                            _threatCategory = text;
                            break;
                        case "severity":
                            _threatSeverity = text;
                            break;
                        case "source":
                            _threatSource = text;
                            break;
                    }

                    _threatProp = null;
                }
            }
        }

        private void FinalizeThreatItem(string sectionKey)
        {
            _inThreatItem = false;
            if (string.IsNullOrWhiteSpace(_threatId))
            {
                return;
            }

            var isGraphThreats = sectionKey == "graph_threats";
            var fallbackCategory = isGraphThreats ? "other" : sectionKey;
            var category = _threatCategory ?? fallbackCategory;

            if (isGraphThreats)
            {
                _graphThreatsCategoryCounts[category] = _graphThreatsCategoryCounts.GetValueOrDefault(category) + 1;
                if (_graphThreatsSamples.Count >= MaxGraphThreatsSample)
                {
                    return;
                }

                _graphThreatsSamples.Add(new BlackboxGraphThreat(
                    _threatId,
                    _threatName ?? string.Empty,
                    category,
                    _threatSeverity ?? "info",
                    string.Empty,
                    _threatSource ?? "public"));
                return;
            }

            if (_arrayCategorySamples.TryGetValue(sectionKey, out var samples) &&
                samples.Count < MaxCategoryArraySample)
            {
                samples.Add(new BlackboxGraphThreat(
                    _threatId,
                    _threatName ?? string.Empty,
                    category,
                    _threatSeverity ?? "info",
                    string.Empty,
                    _threatSource ?? "public"));
            }
        }

        private void ProcessVerifiedScopeToken(ref Utf8JsonReader reader)
        {
            if (reader.CurrentDepth == 2)
            {
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    _scopeProp = reader.GetString();
                    return;
                }

                if (_inVerifiedCounts && reader.TokenType == JsonTokenType.EndObject)
                {
                    _inVerifiedCounts = false;
                    _scopeProp = null;
                    _verifiedCountKey = null;
                    return;
                }

                if (_scopeProp == "built_at")
                {
                    _builtAt = TryReadUnixSeconds(ref reader);
                }
                else if (_scopeProp == "verified_counts" && reader.TokenType == JsonTokenType.StartObject)
                {
                    _inVerifiedCounts = true;
                    _verifiedCountKey = null;
                    _verifiedCounts.Clear();
                    _hasVerifiedScopeCountProperty = false;
                }

                _scopeProp = null;
                return;
            }

            if (reader.CurrentDepth == 3 && _inVerifiedCounts)
            {
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    _verifiedCountKey = reader.GetString();
                    _hasVerifiedScopeCountProperty = true;
                }
                else if (_verifiedCountKey is not null)
                {
                    if (!_verifiedCountKey.Contains(':', StringComparison.Ordinal) &&
                        reader.TokenType == JsonTokenType.Number &&
                        reader.TryGetInt32(out var count) &&
                        count > 0)
                    {
                        _verifiedCounts[_verifiedCountKey] = count;
                    }

                    _verifiedCountKey = null;
                }
            }
        }

        private static bool IsCountedCollectionKey(string key) => key is
            "graph_threats" or
            "injection" or
            "escalation" or
            "dependency" or
            "fileaccess" or
            "skill" or
            "ioc" or
            "secret" or
            "community";

        private static bool IsGraphCategoryKey(string key) => key is
            "injection" or
            "escalation" or
            "dependency" or
            "fileaccess" or
            "skill" or
            "ioc" or
            "secret";

        private static bool IsVerifiedArrayKey(string key) => key is
            "injection" or
            "skill" or
            "escalation" or
            "fileaccess" or
            "graph_threats";

        private static DateTimeOffset? TryReadUnixSeconds(ref Utf8JsonReader reader)
        {
            if (reader.TokenType != JsonTokenType.Number ||
                !reader.TryGetDouble(out var seconds) ||
                !double.IsFinite(seconds) ||
                seconds <= 0)
            {
                return null;
            }

            return DateTimeOffset.FromUnixTimeMilliseconds((long)(seconds * 1000));
        }
    }

    private static RulesetInspection InspectRuleset(string path) =>
        GetOrParseRulesetSnapshot(path).Inspection;

    private static RulesetSnapshot GetOrParseRulesetSnapshot(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                lock (RulesetCacheGate)
                {
                    RulesetCache.Remove(path);
                }

                return RulesetSnapshot.Missing;
            }

            var fingerprint = new RulesetFingerprint(info.Length, info.LastWriteTimeUtc.Ticks);
            lock (RulesetCacheGate)
            {
                if (RulesetCache.TryGetValue(path, out var cached) && cached.Fingerprint == fingerprint)
                {
                    return cached.Snapshot;
                }
            }

            var (snapshot, cacheable) = ParseRulesetStreaming(path);
            if (cacheable && File.GetLastWriteTimeUtc(path).Ticks == fingerprint.LastWriteTimeUtcTicks)
            {
                lock (RulesetCacheGate)
                {
                    if (RulesetCache.Count >= MaxCachedRulesets && !RulesetCache.ContainsKey(path))
                    {
                        RulesetCache.Clear();
                    }

                    RulesetCache[path] = new CachedRulesetEntry(fingerprint, snapshot);
                    if (RulesetParseCountsByPath.Count >= MaxCachedRulesets * 4 && !RulesetParseCountsByPath.ContainsKey(path))
                    {
                        RulesetParseCountsByPath.Clear();
                    }

                    RulesetParseCountsByPath[path] = RulesetParseCountsByPath.GetValueOrDefault(path) + 1;
                }
            }

            return snapshot;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return RulesetSnapshot.Corrupted;
        }
    }

    private static (RulesetSnapshot Snapshot, bool Cacheable) ParseRulesetStreaming(string path)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(StreamBufferInitialSize);
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                StreamBufferInitialSize,
                FileOptions.SequentialScan);

            var state = new JsonReaderState(new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
            });
            var accumulator = new RulesetStreamAccumulator();
            var buffered = 0;
            var isFinalBlock = false;
            var bomChecked = false;

            while (true)
            {
                if (!isFinalBlock)
                {
                    if (buffered == buffer.Length)
                    {
                        var larger = ArrayPool<byte>.Shared.Rent(buffer.Length * 2);
                        Buffer.BlockCopy(buffer, 0, larger, 0, buffered);
                        ArrayPool<byte>.Shared.Return(buffer);
                        buffer = larger;
                    }

                    var read = stream.Read(buffer, buffered, buffer.Length - buffered);
                    if (read == 0)
                    {
                        isFinalBlock = true;
                    }
                    else
                    {
                        buffered += read;
                    }
                }

                if (!bomChecked && (buffered >= 3 || isFinalBlock))
                {
                    bomChecked = true;
                    if (buffered >= 3 &&
                        buffer[0] == 0xEF &&
                        buffer[1] == 0xBB &&
                        buffer[2] == 0xBF)
                    {
                        buffered -= 3;
                        if (buffered > 0)
                        {
                            Buffer.BlockCopy(buffer, 3, buffer, 0, buffered);
                        }
                    }
                }

                var reader = new Utf8JsonReader(buffer.AsSpan(0, buffered), isFinalBlock, state);
                while (reader.Read())
                {
                    accumulator.ProcessToken(ref reader);
                    if (accumulator.Invalid)
                    {
                        return (RulesetSnapshot.Corrupted, true);
                    }
                }

                state = reader.CurrentState;
                var consumed = (int)reader.BytesConsumed;
                var leftover = buffered - consumed;
                if (leftover > 0 && consumed > 0)
                {
                    Buffer.BlockCopy(buffer, consumed, buffer, 0, leftover);
                }

                buffered = leftover;
                if (isFinalBlock)
                {
                    break;
                }
            }

            return (accumulator.BuildSnapshot(), true);
        }
        catch (FileNotFoundException)
        {
            return (RulesetSnapshot.Missing, false);
        }
        catch (DirectoryNotFoundException)
        {
            return (RulesetSnapshot.Missing, false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return (RulesetSnapshot.Corrupted, false);
        }
        catch (JsonException)
        {
            return (RulesetSnapshot.Corrupted, true);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
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
