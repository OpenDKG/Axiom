// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class ThreatShareCliTests
{
    [Theory]
    [InlineData("Report shared with the community", ThreatShareReportStatus.Shared)]
    [InlineData("Already shared with the community", ThreatShareReportStatus.AlreadyShared)]
    [InlineData("Daily report cap reached", ThreatShareReportStatus.CapReached)]
    [InlineData("the indicator was rejected by policy", ThreatShareReportStatus.Rejected)]
    [InlineData("node offline: cannot connect to the local DKG node", ThreatShareReportStatus.RetryableFailure)]
    [InlineData("unexpected output after a completed run", ThreatShareReportStatus.UnknownOutcome)]
    public void Reporter_output_is_classified_without_guessing(string text, ThreatShareReportStatus expected)
    {
        var result = ThreatShareCli.Classify(text, exitCode: 0);

        Assert.Equal(expected, result.Status);
        Assert.Equal(expected == ThreatShareReportStatus.UnknownOutcome, result.Ambiguous);
    }

    [Fact]
    public void An_unknown_completed_run_is_ambiguous_rather_than_retryable()
    {
        var result = ThreatShareCli.Classify(string.Empty, exitCode: 3);

        Assert.Equal(ThreatShareReportStatus.UnknownOutcome, result.Status);
        Assert.True(result.Ambiguous);
        Assert.False(result.Submitted);
        Assert.Contains("exit code 3", result.Outcome, StringComparison.Ordinal);
    }
}
