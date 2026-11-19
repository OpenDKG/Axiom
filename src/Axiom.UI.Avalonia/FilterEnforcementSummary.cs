// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Contracts.Firewall;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>One rule the OS filter refused, as shown on the Firewall page.</summary>
public sealed record RejectedRuleRow(string RuleId, string Reason)
{
    /// <summary>Short id for the list: the first GUID block, or the raw id when it is not a GUID.</summary>
    public string ShortId => Guid.TryParse(RuleId, out var guid)
        ? guid.ToString("D", CultureInfo.InvariantCulture)[..8] + "…"
        : RuleId;
}

/// <summary>
/// Pure mapping of <see cref="FirewallCapabilityReport.FilterEnforcement"/> to the warning block
/// and banner of the Firewall page (review #6). Windows reports no enforcement data, so both stay
/// hidden there and the page is byte-identical to before.
/// </summary>
public sealed record FilterEnforcementSummary
{
    public static readonly FilterEnforcementSummary None = new();

    public IReadOnlyList<RejectedRuleRow> RejectedRules { get; init; } = [];

    /// <summary>Headline of the warning block: "N rule(s) not enforced by the filter".</summary>
    public string RejectedHeadline { get; init; } = string.Empty;

    public bool HasRejectedRules => RejectedRules.Count > 0;

    /// <summary>Banner text when the whole rules file was rejected or the filter dropped events; empty otherwise.</summary>
    public string BannerText { get; init; } = string.Empty;

    public bool HasBanner => BannerText.Length > 0;

    /// <summary>"Filter enforces N rule(s) (generation G)" or empty when nothing was reported.</summary>
    public string EnforcedText { get; init; } = string.Empty;

    /// <summary>
    /// "Filter: connected · generation G verified at hh:mm" / "Filter: connected · generation G pending" /
    /// "Filter: disconnected (last seen hh:mm)"; empty on Windows.
    /// </summary>
    public string ConnectionText { get; init; } = string.Empty;

    public bool HasConnectionText => ConnectionText.Length > 0;

    /// <summary>True when the filter is connected and acknowledged the published generation.</summary>
    public bool IsVerified { get; init; }

    /// <summary>Reason used while the service has not reported the filter's state (Windows, or before the first query).</summary>
    public const string NotReportedReason = "the service has not reported the network filter's state";

    /// <summary>
    /// Why blocks may not be described as enforced (owner point 8): empty only when the filter is
    /// connected, acknowledged the published generation and did not reject the rules file.
    /// </summary>
    public string NotVerifiedReason { get; init; } = NotReportedReason;

    /// <summary>True only with runtime evidence that the published rules are enforced.</summary>
    public bool IsEnforcementVerified => IsVerified && NotVerifiedReason.Length == 0;

    /// <summary>Local time (HH:mm) of the filter's last acknowledgement; empty when unknown.</summary>
    public string VerifiedAtText { get; init; } = string.Empty;

    /// <summary>
    /// "enforced by the {enforcer} (verified HH:mm)" with runtime evidence, otherwise
    /// "not verified as enforced: {reason}". Never claims enforcement without a verified report.
    /// </summary>
    public string EnforcementClause(string enforcer) => IsEnforcementVerified
        ? CoverageText.Length > 0
            ? string.Create(CultureInfo.InvariantCulture, $"installed in the {enforcer} and read back (verified {VerifiedAtText}); {CoverageText}")
            : string.Create(CultureInfo.InvariantCulture, $"enforced by the {enforcer} (verified {VerifiedAtText})")
        : $"not verified as enforced: {NotVerifiedReason}";

    /// <summary>
    /// Linux only (the daemon reports <see cref="FirewallCapabilityReport.ConnectTimeLayer"/>): how many
    /// rules refuse a new process at connect() vs. are nft-only (not race-free). Empty elsewhere.
    /// </summary>
    public string CoverageText { get; init; } = string.Empty;

    /// <summary>Status-bar clause for verified blocks; Linux names the coverage split.</summary>
    public string VerifiedStatusText => CoverageText.Length > 0
        ? $"nft rules read back {VerifiedAtText} · {ShortCoverage}"
        : $"blocks verified {VerifiedAtText}";

    /// <summary>"N connect-time proven · M nft-only (not race-free)" (Linux), empty elsewhere.</summary>
    public string ShortCoverage { get; init; } = string.Empty;

    /// <summary>Coverage sentence for a Linux connect-time layer report; empty when there is none.</summary>
    public static (string Text, string Short) CoverageFor(ConnectTimeLayerReport? layer)
    {
        if (layer is null)
        {
            return (string.Empty, string.Empty);
        }

        var proven = layer.ConnectTimeProvenRules.Count;
        var nftOnly = layer.NftOnlyRules.Count;
        var text = nftOnly == 0
            ? string.Create(CultureInfo.InvariantCulture, $"{proven} rule(s) connect-time proven by the BPF layer (a new process is refused at connect())")
            : string.Create(CultureInfo.InvariantCulture, $"{proven} rule(s) connect-time proven, {nftOnly} nft-only: installed and read back but not race-free — a newly launched process can connect during the ~1 s cgroup attribution window");
        if (!layer.Healthy && !string.Equals(layer.State, "not_configured", StringComparison.Ordinal))
        {
            text += $"; BPF layer {layer.State}";
        }

        var brief = string.Create(CultureInfo.InvariantCulture, $"{proven} connect-time proven · {nftOnly} nft-only (not race-free)");
        return (text, brief);
    }

    public static FilterEnforcementSummary From(FilterEnforcementReport? report, ConnectTimeLayerReport? layer)
    {
        var summary = From(report);
        if (report is null || layer is null)
        {
            return summary;
        }

        var (text, brief) = CoverageFor(layer);
        return summary with
        {
            CoverageText = text,
            ShortCoverage = brief,
            ConnectionText = summary.ConnectionText.Length > 0 ? summary.ConnectionText + " · " + brief : brief,
        };
    }

    public static FilterEnforcementSummary From(FilterEnforcementReport? report)
    {
        if (report is null)
        {
            return None;
        }

        var rejected = report.RejectedRules
            .Select(rule => new RejectedRuleRow(rule.RuleId, rule.Reason))
            .ToArray();

        var banner = new List<string>();
        switch (report.State)
        {
            case FilterEnforcementState.Unavailable:
                banner.Add(PlatformText.Linux
                    ? $"The {PlatformText.FilterTableName} has not been published. Rules are stored but NOT enforced until the daemon publishes it."
                    : "The network filter has not connected. Rules are published but NOT enforced until the extension is activated.");
                break;
            case FilterEnforcementState.Degraded:
                banner.Add(PlatformText.Linux
                    ? string.Create(CultureInfo.InvariantCulture, $"{PlatformText.FilterName} is disconnected (last seen {LocalTime(report.LastSeenUtc)}): table inet axiom is missing or nft cannot be read. Published rules are not known to be enforced; protection is degraded.")
                    : string.Create(CultureInfo.InvariantCulture, $"The network filter is disconnected (last seen {LocalTime(report.LastSeenUtc)}). Published rules are not known to be enforced; protection is degraded."));
                break;
            case FilterEnforcementState.Pending:
                banner.Add(PlatformText.Linux
                    ? string.Create(CultureInfo.InvariantCulture, $"{PlatformText.FilterName} has not acknowledged rules generation {report.PublishedGeneration} yet (table read back with another generation); rules are pending, not verified.")
                    : string.Create(CultureInfo.InvariantCulture, $"The network filter has not acknowledged rules generation {report.PublishedGeneration} yet; rules are pending, not verified."));
                break;
            default:
                break;
        }

        if (report.FileError is { Length: > 0 } error)
        {
            banner.Add(PlatformText.Linux
                ? string.Create(CultureInfo.InvariantCulture, $"{PlatformText.FilterName} rejected the whole rules file ({error}). The previous table (generation {report.Generation}) stays in force; new rules are not enforced.")
                : string.Create(CultureInfo.InvariantCulture, $"The filter rejected the whole rules file ({error}). The previous table (generation {report.Generation}) stays in force; new rules are not enforced."));
        }

        if (report.DroppedEvents > 0)
        {
            banner.Add(string.Create(
                CultureInfo.InvariantCulture,
                $"The filter dropped {report.DroppedEvents} flow event(s); the connection list may be incomplete."));
        }

        return new FilterEnforcementSummary
        {
            RejectedRules = rejected,
            RejectedHeadline = rejected.Length == 0
                ? string.Empty
                : string.Create(CultureInfo.InvariantCulture, $"{rejected.Length} rule(s) not enforced by the filter"),
            BannerText = string.Join(" ", banner),
            IsVerified = report.State == FilterEnforcementState.Verified,
            NotVerifiedReason = NotVerifiedReasonFor(report),
            VerifiedAtText = LocalTime(report.LastAckUtc ?? report.ReportedUtc),
            EnforcedText = report.State == FilterEnforcementState.Verified
                ? string.Create(
                    CultureInfo.InvariantCulture,
                    $"Filter enforces {report.AppliedRuleCount} rule(s) (generation {report.Generation}, verified).")
                : string.Create(
                    CultureInfo.InvariantCulture,
                    $"Filter enforcement {report.State.ToString().ToLowerInvariant()}: generation {report.PublishedGeneration} published, " +
                    $"{(report.AckedGeneration is { } acked ? $"generation {acked} last acknowledged" : "none acknowledged")}."),
            ConnectionText = report.Connected
                ? report.State == FilterEnforcementState.Verified
                    ? string.Create(CultureInfo.InvariantCulture, $"Filter: connected · generation {report.PublishedGeneration} verified at {LocalTime(report.LastAckUtc)}")
                    : string.Create(CultureInfo.InvariantCulture, $"Filter: connected · generation {report.PublishedGeneration} pending acknowledgement")
                : string.Create(CultureInfo.InvariantCulture, $"Filter: disconnected (last seen {LocalTime(report.LastSeenUtc)})"),
        };
    }

    private static string NotVerifiedReasonFor(FilterEnforcementReport report) => report.State switch
    {
        FilterEnforcementState.Unavailable => "the network filter has not connected",
        FilterEnforcementState.Degraded => $"the network filter is disconnected (last seen {LocalTime(report.LastSeenUtc)})",
        FilterEnforcementState.Pending => string.Create(
            CultureInfo.InvariantCulture,
            $"the network filter has not acknowledged rules generation {report.PublishedGeneration}"),
        _ when report.FileError is { Length: > 0 } error => $"the network filter rejected the rules file ({error})",
        FilterEnforcementState.Verified => string.Empty,
        _ => NotReportedReason,
    };

    private static string LocalTime(DateTimeOffset? utc) =>
        utc is { } value ? value.ToLocalTime().ToString("HH:mm", CultureInfo.InvariantCulture) : "never";
}
