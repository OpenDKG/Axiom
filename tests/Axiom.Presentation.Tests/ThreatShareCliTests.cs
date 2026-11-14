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
    [InlineData("hermes: 'blackbox' is not a `hermes` command.", ThreatShareReportStatus.RetryableFailure)]
    [InlineData("Failed to load plugin 'blackbox': load timed out after 10s", ThreatShareReportStatus.RetryableFailure)]
    [InlineData("ModuleNotFoundError: No module named '_cffi_backend'", ThreatShareReportStatus.RetryableFailure)]
    [InlineData("unexpected output after a completed run", ThreatShareReportStatus.UnknownOutcome)]
    public void Reporter_output_is_classified_without_guessing(string text, ThreatShareReportStatus expected)
    {
        var result = ThreatShareCli.Classify(text, exitCode: 0);

        Assert.Equal(expected, result.Status);
        Assert.Equal(expected == ThreatShareReportStatus.UnknownOutcome, result.Ambiguous);
    }

    [Fact]
    public void A_reporter_that_never_ran_is_retryable_and_not_ambiguous()
    {
        Assert.True(ThreatShareCli.IsUnavailable("hermes: 'blackbox' is not a `hermes` command."));
        Assert.False(ThreatShareCli.IsUnavailable("Report shared with the community."));

        var result = ThreatShareCli.Classify("No module named '_cffi_backend'", exitCode: 1);

        Assert.Equal(ThreatShareReportStatus.RetryableFailure, result.Status);
        Assert.False(result.Ambiguous);
        Assert.False(result.Submitted);
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
