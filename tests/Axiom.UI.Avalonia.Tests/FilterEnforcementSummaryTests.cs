// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Presentation;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>Firewall page mapping of the filter's <c>filter.rules</c> report (review #6).</summary>
public sealed class FilterEnforcementSummaryTests
{
    [Fact]
    public void Windows_shape_without_enforcement_data_shows_nothing()
    {
        var summary = FilterEnforcementSummary.From(null);

        Assert.Same(FilterEnforcementSummary.None, summary);
        Assert.False(summary.HasRejectedRules);
        Assert.False(summary.HasBanner);
        Assert.Equal(string.Empty, summary.RejectedHeadline);
        Assert.Equal(string.Empty, summary.EnforcedText);
    }

    [Fact]
    public void Rejected_rules_become_the_warning_block()
    {
        var summary = FilterEnforcementSummary.From(new FilterEnforcementReport
        {
            Generation = 42,
            AppliedRuleCount = 7,
            RejectedRules =
            [
                new FilterRuleRejection { RuleId = "0f8b5c1e-1111-2222-3333-444444444444", Reason = "unknown protocol sctp" },
                new FilterRuleRejection { RuleId = "#3", Reason = "invalid remotePorts 99999" },
            ],
        });

        Assert.True(summary.HasRejectedRules);
        Assert.False(summary.HasBanner);
        Assert.Equal("2 rule(s) not enforced by the filter", summary.RejectedHeadline);
        Assert.Equal("Filter enforces 7 rule(s) (generation 42).", summary.EnforcedText);
        Assert.Collection(
            summary.RejectedRules,
            first =>
            {
                Assert.Equal("0f8b5c1e-1111-2222-3333-444444444444", first.RuleId);
                Assert.Equal("0f8b5c1e…", first.ShortId);
                Assert.Equal("unknown protocol sctp", first.Reason);
            },
            second =>
            {
                Assert.Equal("#3", second.ShortId);
                Assert.Equal("invalid remotePorts 99999", second.Reason);
            });
    }

    [Fact]
    public void File_rejection_and_dropped_events_become_the_banner()
    {
        var fileRejected = FilterEnforcementSummary.From(new FilterEnforcementReport
        {
            Generation = 41,
            AppliedRuleCount = 3,
            FileError = "unreadable: group/world-writable (mode 666)",
        });
        Assert.True(fileRejected.HasBanner);
        Assert.False(fileRejected.HasRejectedRules);
        Assert.Contains("rejected the whole rules file (unreadable: group/world-writable (mode 666))", fileRejected.BannerText, StringComparison.Ordinal);
        Assert.Contains("generation 41", fileRejected.BannerText, StringComparison.Ordinal);

        var dropped = FilterEnforcementSummary.From(new FilterEnforcementReport { AppliedRuleCount = 1, DroppedEvents = 17 });
        Assert.True(dropped.HasBanner);
        Assert.Contains("dropped 17 flow event(s)", dropped.BannerText, StringComparison.Ordinal);

        var clean = FilterEnforcementSummary.From(new FilterEnforcementReport { Generation = 5, AppliedRuleCount = 2 });
        Assert.False(clean.HasBanner);
        Assert.False(clean.HasRejectedRules);
        Assert.Equal("Filter enforces 2 rule(s) (generation 5).", clean.EnforcedText);
    }

    [Fact]
    public async Task Firewall_page_shows_the_rejected_rules_from_the_rules_query()
    {
        var report = new FilterEnforcementReport
        {
            Generation = 9,
            AppliedRuleCount = 1,
            RejectedRules = [new FilterRuleRejection { RuleId = "#0", Reason = "no valid remoteAddresses in [1.2.3]" }],
            DroppedEvents = 2,
        };

        var page = new FirewallPageViewModel(new EnforcementClient(report), new NullUserInteraction());

        await Task.Delay(300);

        Assert.True(page.HasRejectedRules);
        Assert.Equal("1 rule(s) not enforced by the filter", page.RejectedRulesHeadline);
        Assert.Equal("no valid remoteAddresses in [1.2.3]", Assert.Single(page.RejectedRules).Reason);
        Assert.True(page.HasFilterBanner);
        Assert.Contains("dropped 2 flow event(s)", page.FilterBannerText, StringComparison.Ordinal);
        Assert.Equal("Available", page.CapabilityStatusText);

        page.Dispose();
    }

    private sealed class EnforcementClient(FilterEnforcementReport report) : IServiceRequestClient
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
                        ManagedRuleCount = 2,
                        FilterEnforcement = report,
                    },
                    Rules = [],
                    WritesEnabled = false,
                },
                _ => throw new ServiceUnavailableException(IpcErrorCodes.NotSupported, "not supported"),
            };

            return Task.FromResult((T)result);
        }
    }
}
