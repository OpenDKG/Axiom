// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiom.Contracts.Blackbox;

namespace Axiom.UI.Services;

/// <summary>
/// Reads the state files the local Blackbox sync writes beside its dashboard. These are used as a
/// fallback when the dashboard is busy with a graph transfer: the card must still show the last
/// known compiled rules instead of turning into a false "node offline".
/// </summary>
public static class BlackboxLocalState
{
    private static readonly TimeSpan Freshness = TimeSpan.FromMinutes(10);

    public static BlackboxVerifiedSync? TryReadSync(string? root = null, DateTimeOffset? now = null)
    {
        var home = ResolveHome(root);
        if (home is null)
        {
            return null;
        }

        var authoritative = ReadObject(Path.Combine(home, "authoritative-sync.json"));
        if (authoritative is null)
        {
            return null;
        }

        var updated = ReadUnixSeconds(authoritative, "updated_at");
        if (updated is { } timestamp && (now ?? DateTimeOffset.UtcNow) - timestamp > Freshness)
        {
            return null;
        }

        var progress = ReadObject(Path.Combine(home, "sync_progress.json"));
        var counts = progress?["counts"] as JsonArray;
        var downloaded = ReadInt(counts, 0);
        var compiled = ReadInt(counts, 1);
        var total = ReadInt(counts, 2);
        var publicEntries = ReadInt(authoritative, "public_entries");
        var verifiedRules = publicEntries > 0 ? publicEntries : compiled;
        var status = ReadString(authoritative, "status") ?? string.Empty;
        var error = ReadString(authoritative, "error") ?? string.Empty;
        var hasRules = verifiedRules > 0;
        var state = status.ToLowerInvariant() switch
        {
            "done" or "complete" or "completed" or "synced" => "synced",
            "failed" or "cancelled" when !hasRules => "unavailable",
            _ when hasRules => "syncing",
            _ => "unknown",
        };

        var lookup = ReadObject(Path.Combine(home, "verified_lookup_state.json"));
        var lookupState = ReadString(lookup, "state") ?? "unknown";
        var lookupLabel = string.Equals(lookupState, "ok", StringComparison.OrdinalIgnoreCase)
            ? "Live from graph"
            : "Node not answering";
        var lookupText = ReadString(lookup, "reason") ?? string.Empty;

        var phaseText = state switch
        {
            "synced" => $"{verifiedRules:N0} verified rules are available.",
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
            ReadString(authoritative, "phase") ?? string.Empty,
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

        if (entries.Count == 0)
        {
            return null;
        }

        foreach (var group in entries.Values.GroupBy(threat => threat.Category, StringComparer.OrdinalIgnoreCase))
        {
            categoryTotals.TryAdd(group.Key, group.Count());
        }

        var authoritative = ReadObject(Path.Combine(home, "authoritative-sync.json"));
        var total = ReadInt(authoritative, "public_entries");
        return new BlackboxGraphPage(entries.Values.ToList(), total > 0 ? total : entries.Count, Partial: true)
        {
            CategoryTotals = categoryTotals,
        };
    }

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
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "hermes", "blackbox"),
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
