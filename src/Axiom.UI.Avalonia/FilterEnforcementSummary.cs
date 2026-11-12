// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Contracts.Firewall;

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
                banner.Add("The network filter has not connected. Rules are published but NOT enforced until the extension is activated.");
                break;
            case FilterEnforcementState.Degraded:
                banner.Add(string.Create(
                    CultureInfo.InvariantCulture,
                    $"The network filter is disconnected (last seen {LocalTime(report.LastSeenUtc)}). Published rules are not known to be enforced; protection is degraded."));
                break;
            case FilterEnforcementState.Pending:
                banner.Add(string.Create(
                    CultureInfo.InvariantCulture,
                    $"The network filter has not acknowledged rules generation {report.PublishedGeneration} yet; rules are pending, not verified."));
                break;
            default:
                break;
        }

        if (report.FileError is { Length: > 0 } error)
        {
            banner.Add(string.Create(
                CultureInfo.InvariantCulture,
                $"The filter rejected the whole rules file ({error}). The previous table (generation {report.Generation}) stays in force; new rules are not enforced."));
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

    private static string LocalTime(DateTimeOffset? utc) =>
        utc is { } value ? value.ToLocalTime().ToString("HH:mm", CultureInfo.InvariantCulture) : "never";
}
