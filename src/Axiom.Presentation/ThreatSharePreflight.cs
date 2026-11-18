// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Threat;

namespace Axiom.Presentation;

public sealed record ThreatSharePreflightCheck(string Name, bool Passed, string Detail);

public sealed record ThreatSharePreflightResult(IReadOnlyList<ThreatSharePreflightCheck> Checks)
{
    public bool Ready => Checks.All(check => check.Passed);

    public IReadOnlyList<ThreatSharePreflightCheck> Failures =>
        Checks.Where(check => !check.Passed).ToArray();

    /// <summary>One line for the UI; names the refused checks without any free text.</summary>
    public string FailureText =>
        string.Join("; ", Failures.Select(check => $"{check.Name}: {check.Detail}"));
}

/// <summary>
/// The local gate every indicator passes before the reporter is allowed to sign it.
///
/// Reputation is the point: a community graph is only useful while its entries are real. Synthetic
/// lab markers (canaries, EICAR), advertising and tracking hosts, shared hosting and disposable
/// tunnels, and indicators the node already knows must never be submitted, because a rejected or
/// duplicate report costs the reporter's standing. The checks are local; nothing is sent here.
/// </summary>
public static class ThreatSharePreflight
{
    /// <summary>Hosts that host anyone's content, so a report would blame the platform, not a threat.</summary>
    private static readonly string[] SharedHostSuffixes =
    [
        "github.io", "gitlab.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
        "web.app", "firebaseapp.com", "azurewebsites.net", "amazonaws.com", "cloudfront.net",
        "akamaized.net", "fastly.net", "r2.dev", "blogspot.com", "wordpress.com", "wixsite.com",
        "weebly.com", "herokuapp.com", "glitch.me", "repl.co", "codesandbox.io", "stackblitz.io",
        "ngrok.io", "ngrok-free.app", "trycloudflare.com", "duckdns.org", "no-ip.org", "ddns.net",
        "dynu.net", "hopto.org", "zapto.org", "serveo.net", "localtunnel.me", "telebit.io",
        "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
        "github.com", "githubusercontent.com", "raw.githubusercontent.com",
        "azureedge.net", "blob.core.windows.net", "googleusercontent.com",
        "storage.googleapis.com", "edgesuite.net", "edgekey.net",
    ];

    /// <summary>Advertising, analytics and error-reporting hosts: a block there is noise, not a threat.</summary>
    private static readonly string[] TrackingHostSuffixes =
    [
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com",
        "googletagmanager.com", "googletagservices.com", "scorecardresearch.com", "quantserve.com",
        "adnxs.com", "criteo.com", "taboola.com", "outbrain.com", "hotjar.com", "segment.io",
        "mixpanel.com", "amplitude.com", "matomo.cloud", "statcounter.com", "cloudflareinsights.com",
        "sentry.io", "bugsnag.com", "newrelic.com", "datadoghq.com",
    ];

    /// <summary>Values Axiom's own lab produced or that exist only to be examples.</summary>
    private static readonly string[] SyntheticMarkers =
    [
        "eicar", "canary", "axiom-selftest", "selftest", "example.com", "example.org", "example.net",
        "localhost", "127.0.0.1", "::1", "0.0.0.0", ".invalid", ".test", ".example", ".localhost",
    ];

    /// <summary>EICAR test file, in the two hash forms a candidate could carry.</summary>
    private static readonly string[] SyntheticHashes =
    [
        "44d88612fea8a8f36de82e1278abb02f",
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    ];

    public static ThreatSharePreflightResult Evaluate(
        ThreatShareCandidate candidate,
        bool sharingEnabled,
        bool consentPresent,
        bool reporterKeyPresent,
        string? rulesetJson)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        return EvaluateKnownStatus(
            candidate,
            sharingEnabled,
            consentPresent,
            reporterKeyPresent,
            IsAlreadyKnown(candidate.IndicatorType, candidate.Value, rulesetJson));
    }

    /// <summary>Evaluates preflight readiness using a precomputed novelty result without loading the full ruleset string.</summary>
    public static ThreatSharePreflightResult EvaluateKnownStatus(
        ThreatShareCandidate candidate,
        bool sharingEnabled,
        bool consentPresent,
        bool reporterKeyPresent,
        bool alreadyKnownInRuleset)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        var checks = new List<ThreatSharePreflightCheck>
        {
            new("sharing", sharingEnabled, "threat sharing is off"),
            new("reporter terms", consentPresent, "the Blackbox reporter terms are not accepted"),
            new("reporter key", reporterKeyPresent, "the reporter signing key is missing"),
        };

        var normalized = ThreatShareVocabulary.Normalize(candidate.IndicatorType, candidate.Value);
        checks.Add(new(
            "shape",
            string.Equals(normalized, candidate.Value, StringComparison.Ordinal),
            "the indicator is not a normalised, shareable value"));

        var category = CategoryRefusal(candidate.IndicatorType, candidate.Value, candidate.Detail);
        checks.Add(new("category", category is null, category ?? "shareable"));

        checks.Add(new(
            "novelty",
            !alreadyKnownInRuleset,
            "the local ruleset already contains this indicator"));
        checks.Add(new(
            "reason",
            ThreatShareVocabulary.Reasons.Contains(candidate.Reason, StringComparer.OrdinalIgnoreCase),
            "the reason is not in the community vocabulary"));

        return new(checks);
    }

    /// <summary>Formats the canonical ruleset identifier for a candidate indicator.</summary>
    public static string KnownIdentifier(string indicatorType, string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(indicatorType);
        ArgumentException.ThrowIfNullOrEmpty(value);
        return $"ioc:{indicatorType.ToLowerInvariant()}:{value.ToLowerInvariant()}";
    }

    /// <summary>The reason this value must not be shared, or null when its category is acceptable.</summary>
    public static string? CategoryRefusal(string indicatorType, string value, string? detail)
    {
        var text = (value + " " + detail).ToLowerInvariant();
        if (SyntheticMarkers.Any(marker => text.Contains(marker, StringComparison.Ordinal)))
        {
            return "a synthetic lab marker (canary, EICAR or example value)";
        }

        if (SyntheticHashes.Contains(value.Trim().ToLowerInvariant(), StringComparer.Ordinal))
        {
            return "the EICAR test file";
        }

        var host = HostOf(indicatorType, value);
        if (host is null)
        {
            return null;
        }

        if (TrackingHostSuffixes.Any(suffix => IsHostOrSubdomain(host, suffix)))
        {
            return "an advertising, analytics or error-reporting host";
        }

        if (SharedHostSuffixes.Any(suffix => IsHostOrSubdomain(host, suffix)))
        {
            return "shared hosting or a disposable tunnel, not a dedicated threat host";
        }

        return null;
    }

    /// <summary>The host part of a domain or URL indicator, or null for IPs and hashes.</summary>
    public static string? HostOf(string indicatorType, string value)
    {
        var type = (indicatorType ?? string.Empty).Trim().ToLowerInvariant();
        var raw = (value ?? string.Empty).Trim();
        if (type == "domain")
        {
            return raw.TrimEnd('.').ToLowerInvariant();
        }

        if (type == "url" && Uri.TryCreate(raw, UriKind.Absolute, out var uri))
        {
            return uri.IdnHost.TrimEnd('.').ToLowerInvariant();
        }

        return null;
    }

    public static bool IsHostOrSubdomain(string host, string suffix) =>
        string.Equals(host, suffix, StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase);

    /// <summary>True when the local ruleset already carries this exact indicator.</summary>
    public static bool IsAlreadyKnown(string indicatorType, string value, string? rulesetJson)
    {
        if (string.IsNullOrEmpty(rulesetJson) || string.IsNullOrEmpty(indicatorType) || string.IsNullOrEmpty(value))
        {
            return false;
        }

        var identifier = KnownIdentifier(indicatorType, value);
        return rulesetJson.Contains(identifier, StringComparison.OrdinalIgnoreCase);
    }
}
