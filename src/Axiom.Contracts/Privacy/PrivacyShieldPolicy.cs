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
    // All 8 catalogued lists currently exceed 700k combined unique domains (including threat-intel
    // and phishing feeds). Keep comfortable headroom up to 1,000,000 rules without truncation.
    public const int MaxRules = 1_000_000;

    /// <summary>Wire/storage limit for user-entered lists in the initial IPC-backed UI.</summary>
    public const int MaxSettingsDomains = 5_000;

    /// <summary>Default redundant RFC 8484 DoH upstreams (Cloudflare + Quad9 over TLS port 443) so ISP cannot observe DNS traffic.</summary>
    public const string DefaultDohUpstream = "1.1.1.1, 9.9.9.9";

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

    /// <summary>
    /// Security-critical endpoints that third-party catalog lists must never block. Blocking these
    /// silently weakens protection (browser phishing/malware warnings, SmartScreen, Defender cloud
    /// protection, Windows Update, certificate revocation) or breaks core OS behaviour. Each entry
    /// also protects its subdomains. User-entered block rules still apply, so an operator can block
    /// one deliberately; only catalog matches are bypassed.
    /// </summary>
    private static readonly string[] ProtectedSecurityDomains =
    [
        // Google / Mozilla Safe Browsing (Chrome, Edge-on-Chromium fallbacks, Firefox)
        "safebrowsing.googleapis.com",
        "safebrowsing.google.com",
        "sb-ssl.google.com",
        "safebrowsing-cache.google.com",
        "shavar.services.mozilla.com",
        // Microsoft Defender SmartScreen and cloud-delivered protection
        "smartscreen.microsoft.com",
        "smartscreen-prod.microsoft.com",
        "nav.smartscreen.microsoft.com",
        "checkappexec.microsoft.com",
        "urs.microsoft.com",
        "wdcp.microsoft.com",
        "wdcpalt.microsoft.com",
        "definitionupdates.microsoft.com",
        // Windows Update and root/disallowed certificate trust list updates
        "update.microsoft.com",
        "windowsupdate.com",
        "windowsupdate.microsoft.com",
        "delivery.mp.microsoft.com",
        // Windows Push Notification Services & NCSI connectivity probes
        "client.wns.windows.com",
        "wns.windows.com",
        "dns.msftncsi.com",
        "www.msftconnecttest.com",
        // Certificate revocation (OCSP/CRL) for common public CAs
        "ocsp.digicert.com",
        "crl3.digicert.com",
        "crl4.digicert.com",
        "ocsp.pki.goog",
        "crl.pki.goog",
        "o.lencr.org",
        "ocsp.sectigo.com",
        "crl.sectigo.com",
        "oneocsp.microsoft.com",
        "crl.microsoft.com",
        "mscrl.microsoft.com",
    ];

    private static readonly HashSet<string> ProtectedSecuritySet =
        new(ProtectedSecurityDomains, StringComparer.OrdinalIgnoreCase);

    /// <summary>Security-critical domains that catalog blocklists cannot override.</summary>
    public static IReadOnlyList<string> ProtectedSecurityDomainsAll => ProtectedSecurityDomains;

    private readonly record struct PackedRule(PrivacyCategory Category, ushort SourceIndex);

    private readonly Dictionary<string, PackedRule> _overlayBlocked;
    private readonly Dictionary<string, PackedRule> _catalogBlocked;
    private readonly string[] _sourcePalette;
    private readonly HashSet<string> _allowed;

    private PrivacyShieldPolicy(
        Dictionary<string, PackedRule> overlayBlocked,
        Dictionary<string, PackedRule> catalogBlocked,
        string[] sourcePalette,
        HashSet<string> allowed,
        IReadOnlyList<PrivacyShieldStarterRule> starterRulesUsed)
    {
        _overlayBlocked = overlayBlocked;
        _catalogBlocked = catalogBlocked;
        _sourcePalette = sourcePalette;
        _allowed = allowed;
        var overlap = 0;
        if (catalogBlocked.Count > 0)
        {
            foreach (var key in overlayBlocked.Keys)
            {
                if (catalogBlocked.ContainsKey(key))
                {
                    overlap++;
                }
            }
        }

        RuleCount = Math.Min(MaxRules, overlayBlocked.Count + catalogBlocked.Count - overlap);
        StarterRulesUsed = starterRulesUsed;
    }

    public int RuleCount { get; }

    public IReadOnlyList<PrivacyShieldStarterRule> StarterRulesUsed { get; }

    public static IReadOnlyList<PrivacyShieldStarterRule> StarterRulesAll => StarterRules;

    public static PrivacyShieldPolicy Create(
        PrivacyShieldSettings settings,
        IEnumerable<PrivacyShieldStoredRule>? externalRules = null)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var paletteList = new List<string> { "starter", "custom" };
        var paletteMap = new Dictionary<string, ushort>(StringComparer.Ordinal)
        {
            ["starter"] = 0,
            ["custom"] = 1,
        };

        var catalogCount = externalRules is ICollection<PrivacyShieldStoredRule> collection
            ? Math.Min(collection.Count, MaxRules)
            : 0;
        var catalogBlocked = new Dictionary<string, PackedRule>(catalogCount, StringComparer.OrdinalIgnoreCase);

        if (externalRules is not null)
        {
            foreach (var rule in externalRules)
            {
                if (catalogBlocked.Count >= MaxRules)
                {
                    break;
                }

                var normalized = NormalizeDomain(rule.Domain);
                if (normalized is null)
                {
                    continue;
                }

                var sourceId = string.IsNullOrWhiteSpace(rule.SourceId) ? "custom" : rule.SourceId;
                if (!paletteMap.TryGetValue(sourceId, out var sourceIndex))
                {
                    if (paletteList.Count < ushort.MaxValue)
                    {
                        sourceIndex = (ushort)paletteList.Count;
                        paletteList.Add(sourceId);
                        paletteMap[sourceId] = sourceIndex;
                    }
                    else
                    {
                        sourceIndex = 1;
                    }
                }

                catalogBlocked.TryAdd(normalized, new PackedRule(rule.Category, sourceIndex));
            }
        }

        return BuildOverlay(settings, catalogBlocked, [.. paletteList]);
    }

    /// <summary>
    /// Returns a policy updated with <paramref name="settings"/> while sharing the compiled
    /// third-party catalog dictionary so settings edits never duplicate catalog entries.
    /// </summary>
    public PrivacyShieldPolicy WithSettings(PrivacyShieldSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return BuildOverlay(settings, _catalogBlocked, _sourcePalette);
    }

    private static PrivacyShieldPolicy BuildOverlay(
        PrivacyShieldSettings settings,
        Dictionary<string, PackedRule> catalogBlocked,
        string[] sourcePalette)
    {
        var overlayBlocked = new Dictionary<string, PackedRule>(StringComparer.OrdinalIgnoreCase);
        var used = new List<PrivacyShieldStarterRule>();

        foreach (var rule in StarterRules)
        {
            if ((settings.Categories & rule.Category) == 0 || overlayBlocked.Count >= MaxRules)
            {
                continue;
            }

            if (overlayBlocked.TryAdd(rule.Domain, new PackedRule(rule.Category, 0)))
            {
                used.Add(rule);
            }
        }

        foreach (var domain in settings.BlockedDomains)
        {
            if (overlayBlocked.Count >= MaxRules)
            {
                break;
            }

            var normalized = NormalizeDomain(domain);
            if (normalized is not null)
            {
                overlayBlocked.TryAdd(normalized, new PackedRule(PrivacyCategory.Custom, 1));
            }
        }

        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var domain in settings.AllowedDomains)
        {
            var normalized = NormalizeDomain(domain);
            if (normalized is not null)
            {
                allowed.Add(normalized);
            }
        }

        return new PrivacyShieldPolicy(overlayBlocked, catalogBlocked, sourcePalette, allowed, used);
    }

    public DnsPolicyDecision Evaluate(string? domain)
    {
        var normalized = NormalizeDomain(domain);
        if (normalized is null)
        {
            return new DnsPolicyDecision(false, PrivacyCategory.None, null, "Invalid or empty domain name.");
        }

        var span = normalized.AsSpan();
        var allowedLookup = _allowed.GetAlternateLookup<ReadOnlySpan<char>>();
        if (MatchesSuffix(allowedLookup, span))
        {
            return new DnsPolicyDecision(false, PrivacyCategory.None, normalized, "Matched an allow rule.");
        }

        var overlayLookup = _overlayBlocked.GetAlternateLookup<ReadOnlySpan<char>>();
        var catalogLookup = _catalogBlocked.GetAlternateLookup<ReadOnlySpan<char>>();
        var isProtected = MatchesSuffix(
            ProtectedSecuritySet.GetAlternateLookup<ReadOnlySpan<char>>(),
            span);
        var current = span;
        while (true)
        {
            if (overlayLookup.TryGetValue(current, out var overlayEntry))
            {
                return new DnsPolicyDecision(
                    true,
                    overlayEntry.Category,
                    current.ToString(),
                    "Matched a local block rule.",
                    _sourcePalette[overlayEntry.SourceIndex]);
            }

            if (!isProtected && catalogLookup.TryGetValue(current, out var catalogEntry))
            {
                return new DnsPolicyDecision(
                    true,
                    catalogEntry.Category,
                    current.ToString(),
                    "Matched a local block rule.",
                    _sourcePalette[catalogEntry.SourceIndex]);
            }

            var separator = current.IndexOf('.');
            if (separator < 0)
            {
                break;
            }

            current = current[(separator + 1)..];
        }

        if (isProtected)
        {
            return new DnsPolicyDecision(
                false,
                PrivacyCategory.None,
                normalized,
                "Security-critical domain; blocklists cannot block it.");
        }

        return new DnsPolicyDecision(false, PrivacyCategory.None, null, "No local block rule matched.");
    }

    [ThreadStatic]
    private static IdnMapping? t_idnMapping;

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
        if (IsAsciiLowerable(candidate))
        {
            ascii = candidate.ToLowerInvariant();
        }
        else
        {
            try
            {
                ascii = (t_idnMapping ??= new IdnMapping()).GetAscii(candidate).ToLowerInvariant();
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        if (ascii.Length == 0 || ascii.Length > 253 || !ascii.Contains('.'))
        {
            return null;
        }

        var labelStart = 0;
        for (var i = 0; i <= ascii.Length; i++)
        {
            if (i < ascii.Length && ascii[i] != '.')
            {
                continue;
            }

            var labelLength = i - labelStart;
            if (labelLength is 0 or > 63 ||
                ascii[labelStart] == '-' ||
                ascii[i - 1] == '-')
            {
                return null;
            }

            for (var j = labelStart; j < i; j++)
            {
                var character = ascii[j];
                if (!char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_')
                {
                    return null;
                }
            }

            labelStart = i + 1;
        }

        return ascii;
    }

    private static bool IsAsciiLowerable(string value)
    {
        foreach (var ch in value)
        {
            if (ch > 0x7F)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Parses a bounded plain-domain/hosts/DNSMasq/wildcard list. Invalid lines are skipped.</summary>
    public static IReadOnlyList<string> ParseList(string? text, int maxEntries = 100_000)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return [];
        }

        using var reader = new StringReader(text);
        return ParseList(reader, maxEntries);
    }

    /// <summary>Streams and parses a bounded plain-domain/hosts/DNSMasq/wildcard list without full-string allocations.</summary>
    public static IReadOnlyList<string> ParseList(TextReader reader, int maxEntries = 100_000)
    {
        ArgumentNullException.ThrowIfNull(reader);

        var limit = Math.Clamp(maxEntries, 1, MaxRules);
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        while (reader.ReadLine() is { } rawLine)
        {
            if (result.Count >= limit)
            {
                break;
            }

            var span = rawLine.AsSpan().Trim();
            if (span.Length == 0 || span[0] is '#' or '!' or '[')
            {
                continue;
            }

            var comment = span.IndexOf('#');
            if (comment >= 0)
            {
                span = span[..comment].Trim();
                if (span.Length == 0)
                {
                    continue;
                }
            }

            string candidate;
            if (span.StartsWith("address=/", StringComparison.Ordinal))
            {
                var rest = span["address=/".Length..];
                var nextSlash = rest.IndexOf('/');
                if (nextSlash <= 0)
                {
                    continue;
                }

                candidate = rest[..nextSlash].ToString();
            }
            else
            {
                var firstSep = span.IndexOfAny(' ', '\t');
                if (firstSep < 0)
                {
                    candidate = span.ToString();
                }
                else
                {
                    var firstToken = span[..firstSep];
                    var remainder = span[(firstSep + 1)..].TrimStart(" \t");
                    if (remainder.Length > 0 &&
                        (firstToken.SequenceEqual("0.0.0.0") ||
                         firstToken.SequenceEqual("127.0.0.1") ||
                         firstToken.SequenceEqual("::1") ||
                         firstToken.SequenceEqual("::")))
                    {
                        var secondSep = remainder.IndexOfAny(' ', '\t');
                        candidate = (secondSep < 0 ? remainder : remainder[..secondSep]).ToString();
                    }
                    else
                    {
                        candidate = firstToken.ToString();
                    }
                }
            }

            var normalized = NormalizeDomain(candidate);
            if (normalized is not null && seen.Add(normalized))
            {
                result.Add(normalized);
            }
        }

        return result;
    }

    private static bool MatchesSuffix(HashSet<string>.AlternateLookup<ReadOnlySpan<char>> rules, ReadOnlySpan<char> domain)
    {
        var current = domain;
        while (true)
        {
            if (rules.Contains(current))
            {
                return true;
            }

            var separator = current.IndexOf('.');
            if (separator < 0)
            {
                return false;
            }

            current = current[(separator + 1)..];
        }
    }
}
