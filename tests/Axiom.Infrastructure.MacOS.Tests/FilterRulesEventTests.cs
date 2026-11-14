// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.MacOS.Monitoring;

namespace Axiom.Infrastructure.MacOS.Tests;

/// <summary>The daemon side of the <c>filter.rules</c> event (review #6).</summary>
public sealed class FilterRulesEventTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 11, 9, 0, 0, TimeSpan.Zero);

    private const string RulesLine =
        "{\"type\":\"filter.rules\",\"ts\":\"2026-11-11T09:00:00Z\",\"generation\":42,\"applied\":7," +
        "\"rejected\":[{\"id\":\"0f8b5c1e-1111-2222-3333-444444444444\",\"reason\":\"unknown protocol sctp\"}," +
        "{\"id\":\"#3\",\"reason\":\"invalid remotePorts 99999\"}],\"error\":null,\"dropped\":0}";

    [Fact]
    public void ParsesContractRulesEvent()
    {
        var parsed = FlowEventParser.TryParse(RulesLine);

        Assert.NotNull(parsed);
        Assert.Equal(FlowEventType.Rules, parsed.Type);
        Assert.Equal(42, parsed.Generation);
        Assert.Equal(7, parsed.Applied);
        Assert.Null(parsed.Error);
        Assert.Equal(0, parsed.Dropped);
        Assert.Collection(
            parsed.Rejected,
            first =>
            {
                Assert.Equal("0f8b5c1e-1111-2222-3333-444444444444", first.Id);
                Assert.Equal("unknown protocol sctp", first.Reason);
            },
            second =>
            {
                Assert.Equal("#3", second.Id);
                Assert.Equal("invalid remotePorts 99999", second.Reason);
            });
    }

    [Fact]
    public void ParsesFileRejectionWithoutIdAndTolerantly()
    {
        var parsed = FlowEventParser.TryParse(
            "{\"type\":\"filter.rules\",\"generation\":41,\"applied\":3,\"rejected\":[]," +
            "\"error\":\"unreadable: owned by uid 501, expected uid 0\",\"dropped\":12}");

        Assert.NotNull(parsed);
        Assert.Equal("unreadable: owned by uid 501, expected uid 0", parsed.Error);
        Assert.Equal(12, parsed.Dropped);
        Assert.Empty(parsed.Rejected);

        // Wrong types are ignored, entries without id/reason are skipped, the list is capped.
        var many = string.Join(',', Enumerable.Range(0, FlowEventParser.MaxRejectedRules + 10)
            .Select(index => $"{{\"id\":\"r{index}\",\"reason\":\"bad\"}}"));
        var capped = FlowEventParser.TryParse(
            "{\"type\":\"filter.rules\",\"generation\":\"x\",\"applied\":-4,\"rejected\":[" + many + ",{},\"junk\",{\"id\":\"only\"}]}");
        Assert.NotNull(capped);
        Assert.Null(capped.Generation);
        Assert.Equal(0, capped.Applied);
        Assert.Equal(FlowEventParser.MaxRejectedRules, capped.Rejected.Count);

        var noList = FlowEventParser.TryParse("{\"type\":\"filter.rules\",\"rejected\":\"nope\"}");
        Assert.NotNull(noList);
        Assert.Empty(noList.Rejected);

        var onlyId = FlowEventParser.TryParse("{\"type\":\"filter.rules\",\"rejected\":[{\"id\":\"only\"}]}");
        Assert.Equal("rejected by the filter", Assert.Single(onlyId!.Rejected).Reason);
    }

    [Fact]
    public void HelloCarriesDroppedCounter()
    {
        var hello = FlowEventParser.TryParse("{\"type\":\"filter.hello\",\"version\":\"1.0.0\",\"generation\":42,\"dropped\":5}");
        Assert.NotNull(hello);
        Assert.Equal(5, hello.Dropped);
    }

    [Fact]
    public async Task ServerKeepsTheLatestRulesReport()
    {
        using var temp = new TempDirectory();
        var flows = new FlowTable();
        var status = new FilterStatus();
        var time = new ManualTimeProvider(Start);
        var server = new FilterEventServer(MacServicePaths.ForRoot(temp.Path), flows, status, _ => true, time);

        var stream = string.Join('\n',
            "{\"type\":\"filter.hello\",\"version\":\"1.0.0\",\"generation\":41,\"dropped\":0}",
            "{\"type\":\"filter.rules\",\"generation\":41,\"applied\":1,\"rejected\":[],\"error\":null,\"dropped\":0}",
            "{\"type\":\"filter.hello\",\"version\":\"1.0.0\",\"generation\":42,\"dropped\":3}",
            RulesLine);

        var connection = status.ClientConnected();
        await server.ConsumeAsync(new MemoryStream(Encoding.UTF8.GetBytes(stream)), connection, CancellationToken.None);
        status.ClientDisconnected(connection);

        Assert.Equal(4, server.AcceptedEvents);
        Assert.Equal(0, server.RejectedLines);
        Assert.Equal(0, flows.Count);
        Assert.Equal(42, status.LoadedGeneration);
        Assert.Equal(3, status.DroppedEvents); // hello said 3, the rules event said 0: the counter never goes down

        var report = Assert.IsType<FilterRulesReport>(status.Rules);
        Assert.Equal(42, report.Generation);
        Assert.Equal(7, report.Applied);
        Assert.Equal(2, report.Rejected.Count);
        Assert.Null(report.Error);
        Assert.Equal(3, report.Dropped);
        Assert.Equal(Start, report.ReceivedUtc);
    }

    [Fact]
    public void FileRejectionKeepsTheEnforcedGenerationAndIsExposedThroughCapabilities()
    {
        var status = new FilterStatus();
        var connection = status.ClientConnected();
        status.Hello(connection, "1.0.0", 42, 0, Start);
        status.RulesReported(
            connection,
            FlowEventParser.TryParse(
                "{\"type\":\"filter.rules\",\"generation\":42,\"applied\":7,\"rejected\":[]," +
                "\"error\":\"invalid JSON\",\"dropped\":0}")!,
            Start.AddSeconds(5));
        status.ClientDisconnected(connection);

        Assert.Equal(42, status.LoadedGeneration);

        var report = MacFirewallPolicyAdapter.ToEnforcementReport(status.Snapshot(43));
        Assert.Equal("invalid JSON", report.FileError);
        Assert.Equal(42, report.Generation);
        Assert.Equal(7, report.AppliedRuleCount);
        Assert.Empty(report.RejectedRules);
        Assert.Equal(Start.AddSeconds(5), report.ReportedUtc);
        Assert.Equal(43, report.PublishedGeneration);
        Assert.Null(report.AckedGeneration); // a rejected file is not an acknowledgement
        Assert.Equal(FilterEnforcementState.Degraded, report.State); // seen, not connected

        var empty = MacFirewallPolicyAdapter.ToEnforcementReport(new FilterStatus().Snapshot(1));
        Assert.Equal(FilterEnforcementState.Unavailable, empty.State);
        Assert.Equal(-1, empty.Generation);
        Assert.Empty(empty.RejectedRules);
    }

    [Fact]
    public async Task CapabilitiesAndVerifyExposeRejectedRules()
    {
        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var time = new ManualTimeProvider(Start);
        var status = new FilterStatus();
        using var adapter = new MacFirewallPolicyAdapter(paths, status, () => true, time, TimeSpan.Zero);

        var bad = Specs.Block("/usr/bin/curl") with { RemoteAddresses = ["1.2.3"] };
        var good = Specs.Block("/usr/bin/nc");
        Assert.True((await adapter.UpsertOwnedRuleAsync(bad, CancellationToken.None)).Success);
        Assert.True((await adapter.UpsertOwnedRuleAsync(good, CancellationToken.None)).Success);

        // Before the filter reports anything the report says so (no table, nothing acknowledged).
        var before = await adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FilterEnforcementState.Unavailable, before.FilterEnforcement!.State);
        Assert.Equal(-1, before.FilterEnforcement.Generation);
        Assert.Null((await adapter.VerifyAsync(bad, CancellationToken.None)).FilterRejectionReason);

        var connection = status.ClientConnected();
        status.Hello(connection, "1.0.0", 2, 0, time.GetUtcNow());
        status.RulesReported(
            connection,
            FlowEventParser.TryParse(
                "{\"type\":\"filter.rules\",\"generation\":2,\"applied\":1,\"rejected\":[{\"id\":\"" + bad.ManagedRuleId.ToString("D") +
                "\",\"reason\":\"no valid remoteAddresses in [1.2.3]\"}],\"error\":null,\"dropped\":0}")!,
            time.GetUtcNow());

        var capability = await adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FirewallCapabilityStatus.Available, capability.Status);
        Assert.Null(capability.Reason);
        var enforcement = Assert.IsType<FilterEnforcementReport>(capability.FilterEnforcement);
        Assert.Equal(1, enforcement.AppliedRuleCount);
        var rejection = Assert.Single(enforcement.RejectedRules);
        Assert.Equal(bad.ManagedRuleId.ToString("D"), rejection.RuleId);
        Assert.Equal("no valid remoteAddresses in [1.2.3]", rejection.Reason);

        var verifyBad = await adapter.VerifyAsync(bad, CancellationToken.None);
        Assert.True(verifyBad.PresentInOs);
        Assert.True(verifyBad.MatchesSpec);
        Assert.Null(verifyBad.EffectiveAction);
        Assert.Equal("no valid remoteAddresses in [1.2.3]", verifyBad.FilterRejectionReason);
        Assert.Contains(verifyBad.Notes, note => note.Contains("does not enforce it", StringComparison.Ordinal));

        var verifyGood = await adapter.VerifyAsync(good, CancellationToken.None);
        Assert.Equal(FirewallAction.Block, verifyGood.EffectiveAction);
        Assert.Null(verifyGood.FilterRejectionReason);
    }
}
