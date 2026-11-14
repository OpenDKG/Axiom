// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json;
using Axiom.Contracts.Blackbox;

namespace Axiom.Presentation;

/// <summary>Read-only DKG / Blackbox graph tier for indicator context annotations (#231).</summary>
public enum DkgContextTier
{
    Unknown = 0,
    Community = 1,
    Verified = 2,
    LocalFalsePositive = 3,
}

/// <summary>
/// Read-only context badge for one remote host, IP, or indicator. Annotations never trigger
/// automatic firewall or DNS blocks; unknown indicators explicitly remain <c>Unknown</c>.
/// </summary>
public sealed record DkgContextAnnotation
{
    public required string Indicator { get; init; }

    public required DkgContextTier Tier { get; init; }

    public required string BadgeLabel { get; init; }

    public string Category { get; init; } = string.Empty;

    public string Severity { get; init; } = string.Empty;

    public string? KnowledgeAssetUal { get; init; }

    public string? Publisher { get; init; }

    public DateTimeOffset? ObservedUtc { get; init; }

    public int DistinctReporters { get; init; }

    public bool IsStaleCache { get; init; }

    public string? LocalNote { get; init; }

    /// <summary>Invariant for #231: annotations are informational only and never enforce blocks.</summary>
    public bool EnforcesBlock => false;
}

/// <summary>
/// Offline-first, read-only local DKG context lookup (#231). Loads snapshots from local cache or
/// <see cref="BlackboxLocalState"/> off the connection hot path, serves O(1) dictionary lookups,
/// distinguishes Verified vs Community vs Unknown (never reporting "Clean" for misses), and tracks
/// local-only false-positive overrides without mutating remote graphs.
/// </summary>
public sealed class DkgContextAnnotator
{
    public static readonly TimeSpan DefaultStaleThreshold = TimeSpan.FromHours(6);

    private readonly Dictionary<string, BlackboxGraphThreat> _entries;
    private readonly Dictionary<string, string?> _falsePositives = new(StringComparer.OrdinalIgnoreCase);
    private readonly DateTimeOffset? _snapshotUtc;
    private readonly string? _falsePositivesPath;
    private readonly object _gate = new();

    public DkgContextAnnotator(
        IEnumerable<BlackboxGraphThreat>? threats = null,
        DateTimeOffset? snapshotUtc = null,
        string? falsePositivesPath = null)
    {
        _entries = new Dictionary<string, BlackboxGraphThreat>(StringComparer.OrdinalIgnoreCase);
        if (threats is not null)
        {
            foreach (var threat in threats)
            {
                if (!string.IsNullOrWhiteSpace(threat.Identifier))
                {
                    _entries.TryAdd(threat.Identifier.Trim(), threat);
                }
            }
        }

        _snapshotUtc = snapshotUtc;
        _falsePositivesPath = string.IsNullOrWhiteSpace(falsePositivesPath)
            ? null
            : Path.GetFullPath(falsePositivesPath);

        if (_falsePositivesPath is not null)
        {
            LoadFalsePositives(_falsePositivesPath);
        }
    }

    public int CachedIndicatorCount => _entries.Count;

    /// <summary>Loads cached threats exclusively from local Blackbox state files with zero network I/O.</summary>
    public static DkgContextAnnotator LoadFromLocalCache(
        string? blackboxRoot = null,
        string? falsePositivesPath = null,
        DateTimeOffset? now = null)
    {
        var page = BlackboxLocalState.TryReadGraph(blackboxRoot);
        var sync = BlackboxLocalState.TryReadSync(blackboxRoot, now);
        DateTimeOffset? snapshotUtc = sync is not null &&
            DateTimeOffset.TryParse(
                sync.CheckedAt,
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeLocal,
                out var parsed)
            ? parsed
            : null;

        return new DkgContextAnnotator(page?.Threats, snapshotUtc, falsePositivesPath);
    }

    public DkgContextAnnotation Annotate(string? indicator, DateTimeOffset? now = null)
    {
        if (string.IsNullOrWhiteSpace(indicator))
        {
            return UnknownAnnotation(string.Empty, isStale: false);
        }

        var normalized = indicator.Trim();
        var referenceNow = now ?? DateTimeOffset.UtcNow;
        var stale = _snapshotUtc.HasValue && referenceNow - _snapshotUtc.Value > DefaultStaleThreshold;

        lock (_gate)
        {
            if (_falsePositives.TryGetValue(normalized, out var localNote))
            {
                return new DkgContextAnnotation
                {
                    Indicator = normalized,
                    Tier = DkgContextTier.LocalFalsePositive,
                    BadgeLabel = "Marked false positive (local)",
                    IsStaleCache = stale,
                    LocalNote = localNote,
                    ObservedUtc = _snapshotUtc,
                };
            }
        }

        if (!_entries.TryGetValue(normalized, out var threat))
        {
            return UnknownAnnotation(normalized, stale, _snapshotUtc);
        }

        var isCommunity = threat.Source.Contains("community", StringComparison.OrdinalIgnoreCase);
        return new DkgContextAnnotation
        {
            Indicator = normalized,
            Tier = isCommunity ? DkgContextTier.Community : DkgContextTier.Verified,
            BadgeLabel = isCommunity ? "Community sighting" : "Verified threat",
            Category = threat.Category,
            Severity = threat.Severity,
            KnowledgeAssetUal = null,
            Publisher = string.IsNullOrWhiteSpace(threat.Source) ? "local-graph" : threat.Source,
            ObservedUtc = _snapshotUtc,
            DistinctReporters = isCommunity ? 1 : 0,
            IsStaleCache = stale,
        };
    }

    public IReadOnlyList<DkgContextAnnotation> AnnotateBatch(
        IEnumerable<string> indicators,
        int maxBatch = 256,
        DateTimeOffset? now = null)
    {
        ArgumentNullException.ThrowIfNull(indicators);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBatch);

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var results = new List<DkgContextAnnotation>();

        foreach (var indicator in indicators)
        {
            if (results.Count >= maxBatch)
            {
                break;
            }

            if (string.IsNullOrWhiteSpace(indicator))
            {
                continue;
            }

            var trimmed = indicator.Trim();
            if (!seen.Add(trimmed))
            {
                continue;
            }

            results.Add(Annotate(trimmed, now));
        }

        return results;
    }

    public void MarkLocalFalsePositive(string indicator, string? note = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(indicator);

        var normalized = indicator.Trim();
        var cleanNote = string.IsNullOrWhiteSpace(note) ? null : note.Trim();

        lock (_gate)
        {
            _falsePositives[normalized] = cleanNote;
            SaveFalsePositivesLocked();
        }
    }

    public bool ClearLocalFalsePositive(string indicator)
    {
        if (string.IsNullOrWhiteSpace(indicator))
        {
            return false;
        }

        lock (_gate)
        {
            var removed = _falsePositives.Remove(indicator.Trim());
            if (removed)
            {
                SaveFalsePositivesLocked();
            }

            return removed;
        }
    }

    private static DkgContextAnnotation UnknownAnnotation(
        string indicator,
        bool isStale,
        DateTimeOffset? snapshotUtc = null) => new()
        {
            Indicator = indicator,
            Tier = DkgContextTier.Unknown,
            BadgeLabel = "Unknown",
            Severity = "unknown",
            IsStaleCache = isStale,
            ObservedUtc = snapshotUtc,
        };

    private void LoadFalsePositives(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return;
            }

            var json = File.ReadAllText(path);
            var parsed = JsonSerializer.Deserialize<Dictionary<string, string?>>(json);
            if (parsed is null)
            {
                return;
            }

            lock (_gate)
            {
                foreach (var pair in parsed)
                {
                    if (!string.IsNullOrWhiteSpace(pair.Key))
                    {
                        _falsePositives[pair.Key.Trim()] = pair.Value;
                    }
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
        }
    }

    private void SaveFalsePositivesLocked()
    {
        if (_falsePositivesPath is null)
        {
            return;
        }

        try
        {
            var directory = Path.GetDirectoryName(_falsePositivesPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var json = JsonSerializer.Serialize(_falsePositives);
            File.WriteAllText(_falsePositivesPath, json);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}
