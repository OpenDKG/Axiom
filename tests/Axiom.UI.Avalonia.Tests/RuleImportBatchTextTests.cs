// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using Axiom.Contracts.Firewall;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>Rule import status (FND-008): a published-but-unacknowledged or nft-only rule is never
/// reported as plain applied protection.</summary>
public sealed class RuleImportBatchTextTests
{
    private static RuleApplyResult Ok(RuleState state = RuleState.Applied, bool? proven = null) => new()
    {
        Success = true,
        ManagedRuleId = Guid.NewGuid(),
        State = state,
        VerifiedUtc = state == RuleState.Pending ? null : DateTimeOffset.UtcNow,
        ConnectTimeBlockingProven = proven,
    };

    [Fact]
    public void Plain_verified_results_keep_upstream_text()
    {
        Assert.Equal(
            "Applied 2 imported rule(s).",
            RuleApplyResultText.DescribeBatch([Ok(), Ok()], [], "imported rule"));
    }

    [Fact]
    public void Pending_and_not_race_free_results_are_named()
    {
        var text = RuleApplyResultText.DescribeBatch(
            [Ok(proven: true), Ok(proven: false), Ok(RuleState.Pending)],
            [],
            "imported rule");

        Assert.StartsWith("Applied 3 imported rule(s): ", text, StringComparison.Ordinal);
        Assert.Contains("1 connect-time blocking proven", text, StringComparison.Ordinal);
        Assert.Contains("1 installed in", text, StringComparison.Ordinal);
        Assert.Contains("not race-free", text, StringComparison.Ordinal);
        Assert.Contains("not enforced yet", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Failures_are_not_counted_as_applied()
    {
        var failed = new RuleApplyResult
        {
            Success = false,
            ManagedRuleId = Guid.NewGuid(),
            State = RuleState.Failed,
            ErrorCode = "write_gate_closed",
        };

        var text = RuleApplyResultText.DescribeBatch(
            [Ok(), failed],
            new List<string> { "agent: write_gate_closed" },
            "imported rule");

        Assert.Equal("Applied 1 imported rule(s); 1 failed: agent: write_gate_closed", text);
    }
}
