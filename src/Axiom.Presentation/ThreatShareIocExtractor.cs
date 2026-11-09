// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.RegularExpressions;
using Axiom.Contracts.Ai;
using Axiom.Contracts.Threat;

namespace Axiom.Presentation;

/// <summary>
/// Turns an AI Analyst finding into indicator candidates. It is deliberately conservative: only a
/// suspicious or supported alert at high/critical severity qualifies, only well-formed domains,
/// URLs, public IPv4 addresses and SHA-256 digests are taken, and well-known vendor domains,
/// private addresses, file names and local paths are skipped. Nothing is sent here; the candidates
/// land in the Agents-page preview list where the user can see or dismiss them.
/// </summary>
public static partial class ThreatShareIocExtractor
{
    private const int MaxCandidates = 5;

    [GeneratedRegex(@"https?://[^\s""'<>\)\]\}]+", RegexOptions.IgnoreCase)]
    private static partial Regex UrlPattern();

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b")]
    private static partial Regex Ipv4Pattern();

    [GeneratedRegex(@"\b[a-fA-F0-9]{64}\b")]
    private static partial Regex Sha256Pattern();

    [GeneratedRegex(@"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", RegexOptions.IgnoreCase)]
    private static partial Regex DomainPattern();

    private static readonly HashSet<string> BenignDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "microsoft.com",
        "windows.com",
        "windowsupdate.com",
        "google.com",
        "gstatic.com",
        "googleapis.com",
        "cloudflare.com",
        "github.com",
        "githubusercontent.com",
        "openai.com",
        "anthropic.com",
        "opencode.ai",
        "origintrail.io",
        "localhost",
    };

    private static readonly HashSet<string> FileLikeTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "exe", "dll", "sys", "log", "json", "txt", "xml", "csv", "md", "ps1", "bat", "cmd", "msi",
        "tmp", "dat", "db", "sqlite", "pem", "key", "crt", "ini", "yaml", "yml", "zip", "gz",
        "pdf", "docx", "xlsx", "png", "jpg", "html", "lnk",
    };

    public static IReadOnlyList<ThreatShareEnqueueRequest> Extract(AiFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        var status = (finding.Status ?? string.Empty).Trim().ToUpperInvariant();
        var severity = (finding.Severity ?? string.Empty).Trim().ToLowerInvariant();
        if (status is not ("SUSPICIOUS" or "SUPPORTED_ALERT") ||
            severity is not ("high" or "critical"))
        {
            return [];
        }

        var text = string.Join(
            '\n',
            new[] { finding.Summary }
                .Concat(finding.Observations)
                .Concat(finding.EvidenceReferences)
                .Concat(finding.RecommendedActions)
                .Where(value => !string.IsNullOrWhiteSpace(value)));

        var results = new List<ThreatShareEnqueueRequest>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var urlHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string type, string value, string detail)
        {
            if (results.Count >= MaxCandidates)
            {
                return;
            }

            if (ThreatShareVocabulary.Normalize(type, value) is not { } normalized)
            {
                return;
            }

            if (!seen.Add(type + ":" + normalized))
            {
                return;
            }

            results.Add(new ThreatShareEnqueueRequest
            {
                IndicatorType = type,
                Value = normalized,
                Reason = "malware-delivery",
                Context = "in-tool-output",
                Source = ThreatShareSource.AiAnalyst,
                Detail = detail,
                ObservedUtc = finding.AnalysisTimestampUtc,
            });
        }

        foreach (Match match in UrlPattern().Matches(text))
        {
            var url = match.Value.TrimEnd('.', ',', ';', ':');
            if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                urlHosts.Add(uri.Host);
            }

            Add("url", url, "AI Analyst reported this URL in agent evidence.");
        }

        foreach (Match match in Sha256Pattern().Matches(text))
        {
            Add("hash", match.Value, "AI Analyst reported this SHA-256 digest in agent evidence.");
        }

        foreach (Match match in Ipv4Pattern().Matches(text))
        {
            Add("ip", match.Value, "AI Analyst reported this address in agent evidence.");
        }

        foreach (Match match in DomainPattern().Matches(text))
        {
            var domain = match.Value.TrimEnd('.').ToLowerInvariant();
            if (BenignDomains.Contains(domain) || FileLikeTlds.Contains(Tld(domain)) ||
                domain.Contains("..") || urlHosts.Contains(domain) || domain.StartsWith("www.", StringComparison.Ordinal))
            {
                continue;
            }

            Add("domain", domain, "AI Analyst reported this domain in agent evidence.");
        }

        return results;
    }

    private static string Tld(string domain)
    {
        var index = domain.LastIndexOf('.');
        return index < 0 ? string.Empty : domain[(index + 1)..];
    }
}
