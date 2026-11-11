// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net;

namespace Axiom.Contracts.Privacy;

public sealed record PrivacyShieldStarterRule(string Domain, PrivacyCategory Category);

public sealed record DnsPolicyDecision(
    bool Blocked,
    PrivacyCategory Category,
    string? MatchedRule,
    string Reason,
    string SourceId = "");

/// <summary>
/// Deterministic, pure local DNS policy. It does not perform I/O and never trusts list content as
/// executable input. Allow rules win over block rules; both match the domain itself and its parent
/// suffixes.
/// </summary>
public sealed class PrivacyShieldPolicy
{
    // The three catalogued lists currently produce roughly 367k unique domains. Keep headroom
    // for list growth and for future sources without making one large source starve another.
    public const int MaxRules = 500_000;

    /// <summary>Wire/storage limit for user-entered lists in the initial IPC-backed UI.</summary>
    public const int MaxSettingsDomains = 5_000;

    private static readonly PrivacyShieldStarterRule[] StarterRules =
    [
        // Conservative, manually reviewed starter entries. This is not a third-party blocklist.
        new("v10.events.data.microsoft.com", PrivacyCategory.Telemetry),
        new("v20.events.data.microsoft.com", PrivacyCategory.Telemetry),
        new("settings-win.data.microsoft.com", PrivacyCategory.Telemetry),
        new("watson.telemetry.microsoft.com", PrivacyCategory.Telemetry),
        new("telemetry.microsoft.com", PrivacyCategory.Telemetry),
        new("vortex.data.microsoft.com", PrivacyCategory.Telemetry),
        new("mobile.events.data.microsoft.com", PrivacyCategory.Telemetry),
        new("doubleclick.net", PrivacyCategory.Ads),
        new("googlesyndication.com", PrivacyCategory.Ads),
        new("googleadservices.com", PrivacyCategory.Ads),
        new("amazon-adsystem.com", PrivacyCategory.Ads),
        new("adnxs.com", PrivacyCategory.Ads),
        new("criteo.com", PrivacyCategory.Ads),
        new("taboola.com", PrivacyCategory.Ads),
        new("outbrain.com", PrivacyCategory.Ads),
        new("google-analytics.com", PrivacyCategory.Tracking),
        new("googletagmanager.com", PrivacyCategory.Tracking),
        new("scorecardresearch.com", PrivacyCategory.Tracking),
        new("hotjar.com", PrivacyCategory.Tracking),
        new("segment.io", PrivacyCategory.Tracking),
        new("mixpanel.com", PrivacyCategory.Tracking),
        new("amplitude.com", PrivacyCategory.Tracking),
        new("fullstory.com", PrivacyCategory.Analytics),
        new("heap.io", PrivacyCategory.Analytics),
    ];

    private readonly Dictionary<string, (PrivacyCategory Category, string SourceId)> _blocked =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly HashSet<string> _allowed =
        new(StringComparer.OrdinalIgnoreCase);

    private PrivacyShieldPolicy()
    {
    }

    public int RuleCount => _blocked.Count;

    public IReadOnlyList<PrivacyShieldStarterRule> StarterRulesUsed { get; private set; } = [];

    public static IReadOnlyList<PrivacyShieldStarterRule> StarterRulesAll => StarterRules;

    public static PrivacyShieldPolicy Create(
        PrivacyShieldSettings settings,
        IEnumerable<PrivacyShieldStoredRule>? externalRules = null)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var policy = new PrivacyShieldPolicy();
        var used = new List<PrivacyShieldStarterRule>();

        foreach (var rule in StarterRules)
        {
            if ((settings.Categories & rule.Category) == 0 || policy._blocked.Count >= MaxRules)
            {
                continue;
            }

            if (policy._blocked.TryAdd(rule.Domain, (rule.Category, "starter")))
            {
                used.Add(rule);
            }
        }

        foreach (var domain in settings.BlockedDomains)
        {
            if (policy._blocked.Count >= MaxRules)
            {
                break;
            }

            var normalized = NormalizeDomain(domain);
            if (normalized is not null)
            {
                policy._blocked.TryAdd(normalized, (PrivacyCategory.Custom, "custom"));
            }
        }

        if (externalRules is not null)
        {
            foreach (var rule in externalRules)
            {
                if (policy._blocked.Count >= MaxRules)
                {
                    break;
                }

                var normalized = NormalizeDomain(rule.Domain);
                if (normalized is not null)
                {
                    policy._blocked.TryAdd(normalized, (rule.Category, rule.SourceId));
                }
            }
        }

        foreach (var domain in settings.AllowedDomains)
        {
            var normalized = NormalizeDomain(domain);
            if (normalized is not null)
            {
                policy._allowed.Add(normalized);
            }
        }

        policy.StarterRulesUsed = used;
        return policy;
    }

    public DnsPolicyDecision Evaluate(string? domain)
    {
        var normalized = NormalizeDomain(domain);
        if (normalized is null)
        {
            return new DnsPolicyDecision(false, PrivacyCategory.None, null, "Invalid or empty domain name.");
        }

        if (MatchesSuffix(_allowed, normalized))
        {
            return new DnsPolicyDecision(false, PrivacyCategory.None, normalized, "Matched an allow rule.");
        }

        foreach (var candidate in Suffixes(normalized))
        {
            if (_blocked.TryGetValue(candidate, out var entry))
            {
                return new DnsPolicyDecision(
                    true,
                    entry.Category,
                    candidate,
                    "Matched a local block rule.",
                    entry.SourceId);
            }
        }

        return new DnsPolicyDecision(false, PrivacyCategory.None, null, "No local block rule matched.");
    }

    public static string? NormalizeDomain(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var candidate = value.Trim();
        if (candidate.EndsWith('.'))
        {
            candidate = candidate[..^1];
        }

        if (candidate.StartsWith("||", StringComparison.Ordinal) &&
            candidate.EndsWith('^'))
        {
            candidate = candidate[2..^1];
        }
        else if (candidate.StartsWith("*.", StringComparison.Ordinal))
        {
            candidate = candidate[2..];
        }

        if (candidate.Length == 0 || candidate.Length > 253 || IPAddress.TryParse(candidate, out _))
        {
            return null;
        }

        string ascii;
        try
        {
            ascii = new IdnMapping().GetAscii(candidate).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return null;
        }

        if (ascii.Length == 0 || ascii.Length > 253 || !ascii.Contains('.'))
        {
            return null;
        }

        foreach (var label in ascii.Split('.'))
        {
            if (label.Length is 0 or > 63)
            {
                return null;
            }

            if (label[0] == '-' || label[^1] == '-' ||
                label.Any(character => !char.IsLetterOrDigit(character) && character is not '-' and not '_'))
            {
                return null;
            }
        }

        return ascii;
    }

    /// <summary>Parses a bounded plain-domain/hosts/DNSMasq/wildcard list. Invalid lines are skipped.</summary>
    public static IReadOnlyList<string> ParseList(string? text, int maxEntries = 100_000)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return [];
        }

        var limit = Math.Clamp(maxEntries, 1, MaxRules);
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rawLine in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (result.Count >= limit)
            {
                break;
            }

            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith('!') ||
                line.StartsWith('['))
            {
                continue;
            }

            var comment = line.IndexOf('#');
            if (comment >= 0)
            {
                line = line[..comment].Trim();
            }

            if (line.Length == 0)
            {
                continue;
            }

            string candidate;
            var tokens = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length >= 2 &&
                (tokens[0] is "0.0.0.0" or "127.0.0.1" or "::1" or "::"))
            {
                candidate = tokens[1];
            }
            else if (line.StartsWith("address=/", StringComparison.Ordinal))
            {
                var parts = line.Split('/');
                if (parts.Length < 3)
                {
                    continue;
                }

                candidate = parts[1];
            }
            else
            {
                candidate = tokens[0];
            }

            var normalized = NormalizeDomain(candidate);
            if (normalized is not null && seen.Add(normalized))
            {
                result.Add(normalized);
            }
        }

        return result;
    }

    private static bool MatchesSuffix(HashSet<string> rules, string domain) =>
        Suffixes(domain).Any(rules.Contains);

    private static IEnumerable<string> Suffixes(string domain)
    {
        var current = domain;
        while (true)
        {
            yield return current;
            var separator = current.IndexOf('.');
            if (separator < 0)
            {
                yield break;
            }

            current = current[(separator + 1)..];
        }
    }
}
