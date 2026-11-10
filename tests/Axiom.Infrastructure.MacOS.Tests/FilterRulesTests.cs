// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Text.Json;
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.MacOS.Filter;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class FilterRulesTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void RuleSpecMapsToContractRule()
    {
        var id = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");
        var rule = FilterRuleTable.ToFilterRule(new RuleSpec
        {
            ManagedRuleId = id,
            AppPath = " /Applications/Foo.app ",
            Direction = FirewallDirection.Inbound,
            Action = FirewallAction.Allow,
            Protocol = NetworkProtocol.Udp,
            RemoteAddresses = ["10.0.0.0/8", " ", "2001:db8::1"],
            RemotePorts = " 53,5000-5100 ",
            Enabled = false,
            CreatedBy = "uid:501",
        });

        Assert.Equal("0f8fad5b-d9cb-469f-a165-70867728950e", rule.Id);
        Assert.Equal("/Applications/Foo.app", rule.AppPath);
        Assert.Equal("inbound", rule.Direction);
        Assert.Equal("allow", rule.Action);
        Assert.Equal("udp", rule.Protocol);
        Assert.Equal(["10.0.0.0/8", "2001:db8::1"], rule.RemoteAddresses);
        Assert.Equal("53,5000-5100", rule.RemotePorts);
        Assert.False(rule.Enabled);
    }

    [Fact]
    public void TableJsonUsesContractPropertyNames()
    {
        var table = FilterRuleTable.Create([Specs.Block("/usr/bin/curl")], 7);
        using var document = JsonDocument.Parse(table.ToJson());
        var root = document.RootElement;

        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(7, root.GetProperty("generation").GetInt64());
        Assert.True(root.GetProperty("failOpen").GetBoolean());
        var rule = root.GetProperty("rules")[0];
        Assert.Equal("/usr/bin/curl", rule.GetProperty("appPath").GetString());
        Assert.Equal("outbound", rule.GetProperty("direction").GetString());
        Assert.Equal("block", rule.GetProperty("action").GetString());
        Assert.Equal("any", rule.GetProperty("protocol").GetString());
        Assert.Equal(0, rule.GetProperty("remoteAddresses").GetArrayLength());
        Assert.Equal(JsonValueKind.Null, rule.GetProperty("remotePorts").ValueKind);
        Assert.True(rule.GetProperty("enabled").GetBoolean());
    }

    [Fact]
    public void TableIsSortedByIdAndRoundTrips()
    {
        var a = Specs.Block("/a", Guid.Parse("ffffffff-0000-0000-0000-000000000000"));
        var b = Specs.Block("/b", Guid.Parse("00000000-0000-0000-0000-000000000001"));
        var table = FilterRuleTable.Create([a, b], 3);

        Assert.Equal("/b", table.Rules[0].AppPath);
        var parsed = FilterRuleTable.TryParse(table.ToJson());
        Assert.NotNull(parsed);
        Assert.Equal(3, parsed.Generation);
        Assert.True(parsed.Rules[1].SameAs(table.Rules[1]));
        Assert.Null(FilterRuleTable.TryParse("{\"schemaVersion\":99}"));
        Assert.Null(FilterRuleTable.TryParse("not json"));
    }

    [Fact]
    public void MatcherBlockWinsAndUnmatchedIsAllowed()
    {
        var table = new FilterRuleTable
        {
            Generation = 1,
            Rules =
            [
                new FilterRule { Id = "allow", AppPath = "/Applications/Foo.app", Direction = "outbound", Action = "allow" },
                new FilterRule
                {
                    Id = "block",
                    AppPath = "/Applications/Foo.app",
                    Direction = "outbound",
                    Action = "block",
                    Protocol = "tcp",
                    RemoteAddresses = ["93.184.0.0/16"],
                    RemotePorts = "443,8000-8080",
                },
                new FilterRule { Id = "off", AppPath = "*", Direction = "outbound", Action = "block", Enabled = false },
            ],
        };

        FilterFlowFacts Flow(string path, string protocol, string address, int port) =>
            new(path, "outbound", protocol, IPAddress.Parse(address), port);

        var helper = "/Applications/Foo.app/Contents/MacOS/Foo Helper";
        Assert.Equal("block", FilterRuleMatcher.Evaluate(table, Flow(helper, "tcp", "93.184.216.34", 443)).Action);
        Assert.Equal("block", FilterRuleMatcher.Evaluate(table, Flow(helper, "tcp", "::ffff:93.184.216.34", 8080)).Action);
        Assert.Equal("allow", FilterRuleMatcher.Evaluate(table, Flow(helper, "udp", "93.184.216.34", 443)).Action);
        Assert.Equal("allow", FilterRuleMatcher.Evaluate(table, Flow(helper, "tcp", "93.185.1.1", 443)).Action);
        Assert.Equal("allow", FilterRuleMatcher.Evaluate(table, Flow(helper, "tcp", "93.184.216.34", 22)).Action);
        Assert.Equal("allow", FilterRuleMatcher.Evaluate(table, Flow("/Applications/Foo.application/x", "tcp", "93.184.216.34", 443)).Action);
        var unmatched = FilterRuleMatcher.Evaluate(table, Flow("/usr/bin/curl", "tcp", "1.1.1.1", 443));
        Assert.Equal("allow", unmatched.Action);
        Assert.Null(unmatched.Rule);
    }

    [Theory]
    [InlineData("10.0.0.0/8", "10.200.1.1", true)]
    [InlineData("10.0.0.0/8", "11.0.0.1", false)]
    [InlineData("192.168.1.0/25", "192.168.1.127", true)]
    [InlineData("192.168.1.0/25", "192.168.1.128", false)]
    [InlineData("2001:db8::/32", "2001:db8:1::1", true)]
    [InlineData("2001:db8::/32", "10.0.0.1", false)]
    [InlineData("1.2.3.4", "1.2.3.4", true)]
    [InlineData("1.2.3.4/33", "1.2.3.4", false)]
    [InlineData("*", "8.8.8.8", true)]
    public void AddressEntriesMatch(string entry, string address, bool expected) =>
        Assert.Equal(expected, FilterRuleMatcher.AddressMatches([entry], IPAddress.Parse(address)));

    [Fact]
    public void AtomicWriteReplacesFileWithoutLeftovers()
    {
        using var temp = new TempDirectory();
        var path = Path.Combine(temp.Path, "filter", "rules.json");

        FilterRulesFile.WriteAtomic(path, FilterRuleTable.Create([Specs.Block("/a")], 1));
        FilterRulesFile.WriteAtomic(path, FilterRuleTable.Create([], 2));

        Assert.Equal(2, FilterRulesFile.TryRead(path)!.Generation);
        Assert.Equal(["rules.json"], Directory.GetFiles(Path.GetDirectoryName(path)!).Select(Path.GetFileName));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(FilterRulesFile.PublishedMode, File.GetUnixFileMode(path));
        }
    }

    [Fact]
    public async Task AdapterPersistsOwnedRulesAndBumpsGeneration()
    {
        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var time = new ManualTimeProvider(Start);
        var status = new FilterStatus();
        using var adapter = new MacFirewallPolicyAdapter(paths, status, () => true, time);

        var curl = Specs.Block("/usr/bin/curl");
        var applied = await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
        Assert.True(applied.Success, applied.ErrorMessage);
        Assert.Equal(RuleState.Applied, applied.State);

        var table = FilterRulesFile.TryRead(paths.RulesFile)!;
        Assert.Equal(1, table.Generation);
        Assert.Equal("/usr/bin/curl", Assert.Single(table.Rules).AppPath);

        var second = await adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/nc"), CancellationToken.None);
        Assert.True(second.Success);
        Assert.Equal(2, FilterRulesFile.TryRead(paths.RulesFile)!.Generation);

        // A new adapter instance (daemon restart) reads the owned rules back.
        using var restarted = new MacFirewallPolicyAdapter(paths, status, () => true, time);
        Assert.Equal(2, (await restarted.ListOwnedRulesAsync(CancellationToken.None)).Count);
        Assert.Equal(3, await restarted.PublishAsync(CancellationToken.None));

        var verify = await restarted.VerifyAsync(curl, CancellationToken.None);
        Assert.True(verify.PresentInOs);
        Assert.True(verify.MatchesSpec);
        Assert.Equal(FirewallAction.Block, verify.EffectiveAction);
        Assert.Contains(verify.Notes, note => note.Contains("not connected", StringComparison.Ordinal));

        var changed = await restarted.VerifyAsync(curl with { Action = FirewallAction.Allow }, CancellationToken.None);
        Assert.False(changed.MatchesSpec);

        var removed = await restarted.RemoveOwnedRuleAsync(curl.ManagedRuleId, CancellationToken.None);
        Assert.True(removed.Success);
        table = FilterRulesFile.TryRead(paths.RulesFile)!;
        Assert.Equal(4, table.Generation);
        Assert.Equal("/usr/bin/nc", Assert.Single(table.Rules).AppPath);
        Assert.False((await restarted.VerifyAsync(curl, CancellationToken.None)).PresentInOs);
    }

    [Fact]
    public async Task AdapterRefusesWritesWhenGateIsClosed()
    {
        using var temp = new TempDirectory();
        using var adapter = new MacFirewallPolicyAdapter(
            MacServicePaths.ForRoot(temp.Path), new FilterStatus(), () => false, new ManualTimeProvider(Start));

        await Assert.ThrowsAsync<NotSupportedException>(() =>
            adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl"), CancellationToken.None));
        Assert.False(File.Exists(MacServicePaths.ForRoot(temp.Path).RulesFile));
    }

    [Fact]
    public async Task CapabilitiesReportFilterState()
    {
        using var temp = new TempDirectory();
        var time = new ManualTimeProvider(Start);
        var status = new FilterStatus();
        using var adapter = new MacFirewallPolicyAdapter(MacServicePaths.ForRoot(temp.Path), status, () => true, time);

        var noFilter = await adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FirewallCapabilityStatus.Available, noFilter.Status);
        Assert.False(noFilter.FirewallServiceRunning);
        Assert.Contains("has not connected", noFilter.Reason, StringComparison.Ordinal);

        status.Hello("1.0", 0, time.GetUtcNow());
        var withFilter = await adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.True(withFilter.FirewallServiceRunning);
        Assert.Null(withFilter.Reason);

        time.Advance(FilterStatus.HelloLifetime + TimeSpan.FromSeconds(1));
        Assert.False((await adapter.GetCapabilitiesAsync(CancellationToken.None)).FirewallServiceRunning);
    }

    [Fact]
    public async Task CapabilitiesAreUnavailableWhenRulesDirectoryIsNotWritable()
    {
        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        Directory.CreateDirectory(paths.MachineDataDirectory);
        await File.WriteAllTextAsync(paths.FilterDirectory, "a file where the directory should be");
        using var adapter = new MacFirewallPolicyAdapter(paths, new FilterStatus(), () => true, new ManualTimeProvider(Start));

        var report = await adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FirewallCapabilityStatus.Unavailable, report.Status);
        Assert.Contains("not writable", report.Reason, StringComparison.Ordinal);
    }
}
