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
            State = FilterEnforcementState.Verified,
            Connected = true,
            PublishedGeneration = 42,
            AckedGeneration = 42,
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
        Assert.Equal("Filter enforces 7 rule(s) (generation 42, verified).", summary.EnforcedText);
        Assert.True(summary.IsVerified);
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
            State = FilterEnforcementState.Pending,
            Connected = true,
            PublishedGeneration = 42,
            AckedGeneration = 41,
            Generation = 41,
            AppliedRuleCount = 3,
            FileError = "unreadable: group/world-writable (mode 666)",
        });
        Assert.True(fileRejected.HasBanner);
        Assert.False(fileRejected.HasRejectedRules);
        Assert.Contains("rejected the whole rules file (unreadable: group/world-writable (mode 666))", fileRejected.BannerText, StringComparison.Ordinal);
        Assert.Contains("generation 41", fileRejected.BannerText, StringComparison.Ordinal);

        var dropped = FilterEnforcementSummary.From(new FilterEnforcementReport { State = FilterEnforcementState.Verified, Connected = true, AppliedRuleCount = 1, DroppedEvents = 17 });
        Assert.True(dropped.HasBanner);
        Assert.Contains("dropped 17 flow event(s)", dropped.BannerText, StringComparison.Ordinal);

        var clean = FilterEnforcementSummary.From(new FilterEnforcementReport
        {
            State = FilterEnforcementState.Verified,
            Connected = true,
            PublishedGeneration = 5,
            AckedGeneration = 5,
            LastAckUtc = new DateTimeOffset(2026, 11, 12, 9, 30, 0, TimeSpan.Zero),
            Generation = 5,
            AppliedRuleCount = 2,
        });
        Assert.False(clean.HasBanner);
        Assert.False(clean.HasRejectedRules);
        Assert.Equal("Filter enforces 2 rule(s) (generation 5, verified).", clean.EnforcedText);
        Assert.StartsWith("Filter: connected · generation 5 verified at ", clean.ConnectionText, StringComparison.Ordinal);
    }

    /// <summary>Review 2026-11-12: the page must never read "enforces" for a table the filter has not acknowledged.</summary>
    [Fact]
    public void Unverified_enforcement_is_a_banner_never_an_enforces_line()
    {
        var absent = FilterEnforcementSummary.From(new FilterEnforcementReport { State = FilterEnforcementState.Unavailable, PublishedGeneration = 3 });
        Assert.True(absent.HasBanner);
        Assert.False(absent.IsVerified);
        Assert.Contains("NOT enforced", absent.BannerText, StringComparison.Ordinal);
        Assert.DoesNotContain("Filter enforces", absent.EnforcedText, StringComparison.Ordinal);
        Assert.Equal("Filter enforcement unavailable: generation 3 published, none acknowledged.", absent.EnforcedText);
        Assert.Equal("Filter: disconnected (last seen never)", absent.ConnectionText);

        var lastSeen = new DateTimeOffset(2026, 11, 12, 9, 30, 0, TimeSpan.Zero);
        var degraded = FilterEnforcementSummary.From(new FilterEnforcementReport
        {
            State = FilterEnforcementState.Degraded,
            Connected = false,
            PublishedGeneration = 4,
            AckedGeneration = 4,
            LastSeenUtc = lastSeen,
            Generation = 4,
            AppliedRuleCount = 2,
        });
        Assert.True(degraded.HasBanner);
        Assert.Contains("disconnected (last seen " + lastSeen.ToLocalTime().ToString("HH:mm", System.Globalization.CultureInfo.InvariantCulture) + ")", degraded.BannerText, StringComparison.Ordinal);
        Assert.Contains("protection is degraded", degraded.BannerText, StringComparison.Ordinal);
        Assert.StartsWith("Filter: disconnected (last seen ", degraded.ConnectionText, StringComparison.Ordinal);
        Assert.Equal("Filter enforcement degraded: generation 4 published, generation 4 last acknowledged.", degraded.EnforcedText);

        var pending = FilterEnforcementSummary.From(new FilterEnforcementReport
        {
            State = FilterEnforcementState.Pending,
            Connected = true,
            PublishedGeneration = 6,
            AckedGeneration = 5,
            Generation = 5,
            AppliedRuleCount = 2,
        });
        Assert.True(pending.HasBanner);
        Assert.Contains("has not acknowledged rules generation 6", pending.BannerText, StringComparison.Ordinal);
        Assert.Equal("Filter: connected · generation 6 pending acknowledgement", pending.ConnectionText);
        Assert.Equal("Filter enforcement pending: generation 6 published, generation 5 last acknowledged.", pending.EnforcedText);
    }

    [Fact]
    public async Task Firewall_page_shows_the_rejected_rules_from_the_rules_query()
    {
        var report = new FilterEnforcementReport
        {
            State = FilterEnforcementState.Verified,
            Connected = true,
            PublishedGeneration = 9,
            AckedGeneration = 9,
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

    /// <summary>Review 2026-11-12 #4: the live filter state must be re-queried while the page is visible, throttled.</summary>
    [Fact]
    public async Task Firewall_page_requeries_enforcement_when_stale()
    {
        var client = new EnforcementClient(new FilterEnforcementReport { State = FilterEnforcementState.Verified, Connected = true });
        var page = new FirewallPageViewModel(client, new NullUserInteraction());

        // The fake client completes synchronously, so the constructor's refresh has finished by now.
        var initial = client.RulesQueries;
        Assert.Equal(1, initial);
        var lastRefresh = page.LastEnforcementRefreshUtc;
        Assert.NotEqual(default, lastRefresh);

        // "Now" is derived from the page's own last-refresh instant rather than the wall clock, so a
        // stalled test host (or a clock step on a loaded VM) cannot make the first call look stale.
        page.RefreshEnforcementIfStale(lastRefresh + FirewallPageViewModel.EnforcementRefreshInterval - TimeSpan.FromMilliseconds(1));
        Assert.Equal(initial, client.RulesQueries); // fresh: no extra query

        page.RefreshEnforcementIfStale(lastRefresh + FirewallPageViewModel.EnforcementRefreshInterval);
        Assert.Equal(initial + 1, client.RulesQueries);
        Assert.True(page.LastEnforcementRefreshUtc >= lastRefresh);

        page.Dispose();
    }

    /// <summary>
    /// The Recheck button on the Network Control page binds <c>RefreshCommand</c>. The
    /// source-generated command must exist, be executable once the page has loaded, and re-query
    /// the rules; a missing command fails the binding and Avalonia greys the button out.
    /// </summary>
    [Fact]
    public async Task Recheck_binds_an_executable_refresh_command()
    {
        var client = new EnforcementClient(new FilterEnforcementReport { State = FilterEnforcementState.Verified, Connected = true });
        var page = new FirewallPageViewModel(client, new NullUserInteraction());

        var property = typeof(FirewallPageViewModel).GetProperty("RefreshCommand");
        Assert.NotNull(property);
        var command = Assert.IsAssignableFrom<CommunityToolkit.Mvvm.Input.IAsyncRelayCommand>(property!.GetValue(page));
        Assert.True(command.CanExecute(null));

        var before = client.RulesQueries;
        await command.ExecuteAsync(null);
        Assert.Equal(before + 1, client.RulesQueries);
        Assert.True(command.CanExecute(null));

        page.Dispose();
    }

    private sealed class EnforcementClient(FilterEnforcementReport report) : IServiceRequestClient
    {
        public int RulesQueries { get; private set; }

        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            if (command == IpcCommandTypes.RulesQuery)
            {
                RulesQueries++;
            }

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
