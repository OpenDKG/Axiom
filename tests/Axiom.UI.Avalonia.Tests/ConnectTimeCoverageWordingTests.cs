// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// PR #276 round 3, item 4: a Linux nft-only rule is "installed/read back, not race-free"; only a
/// rule with a read-back connect-time verdict may be worded as connect-time blocking. Windows and
/// macOS report no coverage (null), so their text is unchanged.
/// </summary>
public sealed class ConnectTimeCoverageWordingTests
{
    private static readonly DateTimeOffset At = new(2026, 11, 14, 10, 0, 0, TimeSpan.Zero);

    private static FilterEnforcementReport Verified() => new()
    {
        State = FilterEnforcementState.Verified,
        Connected = true,
        PublishedGeneration = 5,
        AckedGeneration = 5,
        Generation = 5,
        AppliedRuleCount = 2,
        LastAckUtc = At,
        ReportedUtc = At,
    };

    [Fact]
    public void Linux_summary_with_nft_only_rules_never_reads_as_plain_enforced()
    {
        var layer = new ConnectTimeLayerReport { State = "active", Healthy = true, ConnectTimeProvenRules = [Guid.NewGuid()], NftOnlyRules = [Guid.NewGuid()] };

        var summary = FilterEnforcementSummary.From(Verified(), layer);

        var clause = summary.EnforcementClause("nftables firewall");
        Assert.StartsWith("installed in the nftables firewall and read back", clause, StringComparison.Ordinal);
        Assert.Contains("1 nft-only", clause, StringComparison.Ordinal);
        Assert.Contains("not race-free", clause, StringComparison.Ordinal);
        Assert.DoesNotContain("enforced by", clause, StringComparison.Ordinal);
        Assert.StartsWith("nft rules read back", summary.VerifiedStatusText, StringComparison.Ordinal);
        Assert.Contains("1 nft-only (not race-free)", summary.ConnectionText, StringComparison.Ordinal);
    }

    [Fact]
    public void Without_a_layer_report_the_wording_is_unchanged()
    {
        var summary = FilterEnforcementSummary.From(Verified(), null);

        Assert.StartsWith("enforced by the network filter (verified ", summary.EnforcementClause("network filter"), StringComparison.Ordinal);
        Assert.StartsWith("blocks verified ", summary.VerifiedStatusText, StringComparison.Ordinal);
        Assert.Equal(FilterEnforcementSummary.From(Verified()).ConnectionText, summary.ConnectionText);
    }

    [Fact]
    public void Rule_result_and_row_say_nft_only_is_not_race_free()
    {
        var id = Guid.NewGuid();
        var nftOnly = new RuleApplyResult { Success = true, ManagedRuleId = id, State = RuleState.Applied, VerifiedUtc = At, ConnectTimeBlockingProven = false, CoverageReason = "scoped rules are not expressed by the BPF layer" };
        var proven = nftOnly with { ConnectTimeBlockingProven = true, CoverageReason = null };
        var windows = nftOnly with { ConnectTimeBlockingProven = null, CoverageReason = null };

        Assert.Contains("read back", RuleApplyResultText.Describe(nftOnly, "Block rule"), StringComparison.Ordinal);
        Assert.Contains("not race-free", RuleApplyResultText.Describe(nftOnly, "Block rule"), StringComparison.Ordinal);
        Assert.Contains("connect-time blocking proven", RuleApplyResultText.Describe(proven, "Block rule"), StringComparison.Ordinal);
        Assert.Equal($"Block rule applied; verified at {At:HH:mm:ss}.", RuleApplyResultText.Describe(windows, "Block rule"));

        var spec = new RuleSpec { ManagedRuleId = id, AppPath = "/usr/bin/curl", Direction = FirewallDirection.Outbound, Action = FirewallAction.Block, CreatedBy = "uid:1000" };
        var rule = new ManagedRule { ManagedRuleId = id, OsRuleName = "Axiom::x", Spec = spec, State = RuleState.Applied, ConnectTimeBlockingProven = false };
        Assert.Equal("Applied · nft-only (not race-free)", new FirewallRuleRow(rule).StateText);
        Assert.Equal("Applied", new FirewallRuleRow(rule with { ConnectTimeBlockingProven = null }).StateText);
    }
}
