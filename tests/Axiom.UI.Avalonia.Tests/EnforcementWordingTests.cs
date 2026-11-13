// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Presentation;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// Owner point 8: user-facing text never describes enforcement as operational without runtime
/// evidence, and the Overview line claims only what is switched on.
/// </summary>
public sealed class EnforcementWordingTests
{
    private static readonly DateTimeOffset AckUtc = new(2026, 11, 13, 10, 42, 0, TimeSpan.Zero);

    private static string AckLocal => AckUtc.ToLocalTime().ToString("HH:mm", CultureInfo.InvariantCulture);

    private static FilterEnforcementSummary Verified() => FilterEnforcementSummary.From(new FilterEnforcementReport
    {
        State = FilterEnforcementState.Verified,
        Connected = true,
        PublishedGeneration = 4,
        AckedGeneration = 4,
        Generation = 4,
        LastAckUtc = AckUtc,
    });

    private static FilterEnforcementSummary Unavailable() =>
        FilterEnforcementSummary.From(new FilterEnforcementReport { State = FilterEnforcementState.Unavailable });

    [Fact]
    public void Enforcement_clause_requires_a_verified_report()
    {
        Assert.False(FilterEnforcementSummary.None.IsEnforcementVerified);
        Assert.Equal(
            "not verified as enforced: the service has not reported the network filter's state",
            FilterEnforcementSummary.None.EnforcementClause("AxiomFilter network extension"));

        Assert.True(Verified().IsEnforcementVerified);
        Assert.Equal(
            $"enforced by the AxiomFilter network extension (verified {AckLocal})",
            Verified().EnforcementClause("AxiomFilter network extension"));

        Assert.Equal("the network filter has not connected", Unavailable().NotVerifiedReason);
        Assert.Equal(
            "the network filter has not acknowledged rules generation 7",
            FilterEnforcementSummary.From(new FilterEnforcementReport { State = FilterEnforcementState.Pending, Connected = true, PublishedGeneration = 7 }).NotVerifiedReason);
        Assert.StartsWith(
            "the network filter is disconnected (last seen ",
            FilterEnforcementSummary.From(new FilterEnforcementReport { State = FilterEnforcementState.Degraded, LastSeenUtc = AckUtc }).NotVerifiedReason,
            StringComparison.Ordinal);

        // A later file rejection revokes the verified claim even when the state still says Verified.
        var rejectedFile = FilterEnforcementSummary.From(new FilterEnforcementReport
        {
            State = FilterEnforcementState.Verified,
            Connected = true,
            LastAckUtc = AckUtc,
            FileError = "unreadable",
        });
        Assert.False(rejectedFile.IsEnforcementVerified);
        Assert.Equal("the network filter rejected the rules file (unreadable)", rejectedFile.NotVerifiedReason);
    }

    [Fact]
    public void Applications_page_claims_blocks_only_when_verified()
    {
        Assert.Equal(
            $"Firewall rules are enabled (Axiom Shield is on). Blocks are enforced by the AxiomFilter network extension (verified {AckLocal}).",
            AppsPageViewModel.UnixWriteStatus(true, Verified(), "AxiomFilter network extension"));
        Assert.Equal(
            "Firewall rules are enabled (Axiom Shield is on). Blocks are not verified as enforced: the network filter has not connected.",
            AppsPageViewModel.UnixWriteStatus(true, Unavailable(), "AxiomFilter network extension"));
        Assert.Equal(
            "Firewall rules are off. Turn on Axiom Shield on the Firewall page to create block rules.",
            AppsPageViewModel.UnixWriteStatus(false, FilterEnforcementSummary.None, "AxiomFilter network extension"));
    }

    [Theory]
    [InlineData(false, false, false, OverviewPageViewModel.ReadOnlyStatus)]
    [InlineData(true, false, false, "Firewall writes enabled; no Axiom rules active. No telemetry.")]
    [InlineData(false, false, true, "Protection active: Privacy Shield on; no firewall write. No telemetry.")]
    [InlineData(true, false, true, "Protection active: Privacy Shield on; firewall writes enabled. No telemetry.")]
    [InlineData(true, true, false, "Protection active: Axiom rules apply; firewall writes enabled. No telemetry.")]
    [InlineData(true, true, true, "Protection active: Axiom rules apply; Privacy Shield on; firewall writes enabled. No telemetry.")]
    public void Overview_line_on_windows_claims_only_what_is_on(bool writes, bool protection, bool shield, string expected)
    {
        Assert.Equal(expected, OverviewPageViewModel.ComposeStatus(new OverviewProtectionState(writes, protection, shield, Enforcement: null)));
    }

    [Fact]
    public void Overview_line_keeps_upstream_text_without_state_and_follows_the_filter_elsewhere()
    {
        Assert.Equal("Read-only inventory. No driver, no firewall write, no telemetry.", OverviewPageViewModel.ComposeStatus(null));

        Assert.Equal(
            "Protection active: Axiom rules apply; firewall writes enabled. No telemetry.",
            OverviewPageViewModel.ComposeStatus(new OverviewProtectionState(true, true, false, Verified())));

        var unverified = OverviewPageViewModel.ComposeStatus(new OverviewProtectionState(true, true, false, Unavailable()));
        Assert.Equal(
            "Protection active: Axiom rules not verified as enforced: the network filter has not connected; firewall writes enabled. No telemetry.",
            unverified);
        Assert.DoesNotContain("rules apply", unverified, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Firewall_notice_follows_the_filter_report()
    {
        var page = new FirewallPageViewModel(new WritableClient(new FilterEnforcementReport { State = FilterEnforcementState.Unavailable }), new NullUserInteraction());
        await page.RefreshCommand.ExecuteAsync(null);

        Assert.True(page.WritesEnabled);
        if (OperatingSystem.IsWindows())
        {
            // Windows text is unchanged.
            Assert.Equal(
                "Axiom Shield is on. Rules are read and written through the elevated local service with the documented INetFwPolicy2 COM objects. Every change is confirmed and audited.",
                page.NoticeText);
        }
        else
        {
            Assert.Contains("not verified as enforced: the network filter has not connected", page.NoticeText, StringComparison.Ordinal);
            Assert.DoesNotContain("enforced by the", page.NoticeText, StringComparison.Ordinal);
        }

        page.Dispose();
    }

    private sealed class WritableClient(FilterEnforcementReport report) : IServiceRequestClient
    {
        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            object result = command switch
            {
                IpcCommandTypes.RulesQuery => new FirewallRulesSnapshot
                {
                    Capability = new FirewallCapabilityReport
                    {
                        Status = FirewallCapabilityStatus.Available,
                        ManagedRulesReadable = true,
                        FilterEnforcement = report,
                    },
                    Rules = [],
                    WritesEnabled = true,
                },
                _ => throw new ServiceUnavailableException(IpcErrorCodes.NotSupported, "not supported"),
            };

            return Task.FromResult((T)result);
        }
    }
}
