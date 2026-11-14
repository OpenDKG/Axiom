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

    /// <summary>Review #18: the shared fixture is the contract between the .NET reference matcher and the Swift filter.</summary>
    private static JsonDocument LoadContract() =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "rules-cases.json")));

    [Fact]
    public void ContractFixtureRuleSetsMatchTheReferenceMatcher()
    {
        using var contract = LoadContract();
        var checks = 0;
        foreach (var set in contract.RootElement.GetProperty("ruleSets").EnumerateArray())
        {
            var setName = set.GetProperty("name").GetString();
            var table = FilterRuleTable.TryParse(set.GetProperty("table").GetRawText());
            Assert.True(table is not null, $"rule set '{setName}' must parse");

            foreach (var item in set.GetProperty("cases").EnumerateArray())
            {
                var caseName = $"{setName} / {item.GetProperty("name").GetString()}";
                var flow = item.GetProperty("flow");
                var remote = flow.GetProperty("remoteAddress").ValueKind == JsonValueKind.Null
                    ? null
                    : IPAddress.Parse(flow.GetProperty("remoteAddress").GetString()!);
                var facts = new FilterFlowFacts(
                    flow.GetProperty("appPath").ValueKind == JsonValueKind.Null ? string.Empty : flow.GetProperty("appPath").GetString()!,
                    flow.GetProperty("direction").GetString()!,
                    flow.GetProperty("protocol").GetString()!,
                    remote,
                    flow.GetProperty("remotePort").GetInt32());

                var verdict = FilterRuleMatcher.Evaluate(table!, facts);
                Assert.True(item.GetProperty("action").GetString() == verdict.Action, $"{caseName}: expected {item.GetProperty("action").GetString()}, got {verdict.Action}");
                if (item.TryGetProperty("ruleId", out var ruleId))
                {
                    var expected = ruleId.ValueKind == JsonValueKind.Null ? null : ruleId.GetString();
                    Assert.True(expected == verdict.Rule?.Id, $"{caseName}: expected rule {expected ?? "none"}, got {verdict.Rule?.Id ?? "none"}");
                }

                checks++;
            }
        }

        Assert.True(checks >= 20, "the fixture lost cases");
    }

    [Fact]
    public void ContractFixtureAddressEntriesMatchTheReferenceMatcher()
    {
        using var contract = LoadContract();
        foreach (var item in contract.RootElement.GetProperty("addressEntries").EnumerateArray())
        {
            var entry = item.GetProperty("entry").GetString()!;
            var address = IPAddress.Parse(item.GetProperty("address").GetString()!);
            var expected = item.GetProperty("expected").GetBoolean();

            Assert.True(expected == FilterRuleMatcher.AddressMatches([entry], address), $"{item.GetProperty("name").GetString()}: '{entry}' vs {address}");
        }
    }

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
        using var adapter = new MacFirewallPolicyAdapter(paths, status, () => true, time, TimeSpan.Zero);

        var curl = Specs.Block("/usr/bin/curl");
        var applied = await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
        Assert.True(applied.Success, applied.ErrorMessage);
        // No connected extension: published, never "applied" (review P0 #2).
        Assert.Equal(RuleState.Pending, applied.State);
        Assert.Null(applied.VerifiedUtc);

        var table = FilterRulesFile.TryRead(paths.RulesFile)!;
        Assert.Equal(1, table.Generation);
        Assert.Equal("/usr/bin/curl", Assert.Single(table.Rules).AppPath);

        var second = await adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/nc"), CancellationToken.None);
        Assert.True(second.Success);
        Assert.Equal(RuleState.Pending, second.State);
        Assert.Equal(2, FilterRulesFile.TryRead(paths.RulesFile)!.Generation);

        // A new adapter instance (daemon restart) reads the owned rules back.
        using var restarted = new MacFirewallPolicyAdapter(paths, status, () => true, time, TimeSpan.Zero);
        Assert.Equal(2, (await restarted.ListOwnedRulesAsync(CancellationToken.None)).Count);
        Assert.All(await restarted.ListOwnedRulesAsync(CancellationToken.None), rule => Assert.Equal(RuleState.Pending, rule.State));
        Assert.Equal(3, await restarted.PublishAsync(CancellationToken.None));

        var verify = await restarted.VerifyAsync(curl, CancellationToken.None);
        Assert.True(verify.PresentInOs);
        Assert.True(verify.MatchesSpec);
        Assert.Null(verify.EffectiveAction);
        Assert.False(verify.EnforcementVerified);
        Assert.Contains(verify.Notes, note => note.Contains("never connected", StringComparison.Ordinal));

        var changed = await restarted.VerifyAsync(curl with { Action = FirewallAction.Allow }, CancellationToken.None);
        Assert.False(changed.MatchesSpec);

        var removed = await restarted.RemoveOwnedRuleAsync(curl.ManagedRuleId, CancellationToken.None);
        Assert.True(removed.Success);
        Assert.Null(removed.VerifiedUtc);
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
    public async Task CapabilitiesReportLiveConnectionNotRecentHello()
    {
        using var temp = new TempDirectory();
        var time = new ManualTimeProvider(Start);
        var status = new FilterStatus();
        using var adapter = new MacFirewallPolicyAdapter(MacServicePaths.ForRoot(temp.Path), status, () => true, time, TimeSpan.Zero);

        var noFilter = await adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FirewallCapabilityStatus.Degraded, noFilter.Status);
        Assert.False(noFilter.FirewallServiceRunning);
        Assert.Contains("has not connected", noFilter.Reason, StringComparison.Ordinal);

        // A hello without a live connection (High #4) must not count as running.
        var previous = status.ClientConnected();
        status.Hello(previous, "1.0", 0, time.GetUtcNow());
        status.ClientDisconnected(previous);
        var helloOnly = await adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.False(helloOnly.FirewallServiceRunning);
        Assert.Equal(FirewallCapabilityStatus.Degraded, helloOnly.Status);
        Assert.Equal(FilterEnforcementState.Degraded, helloOnly.FilterEnforcement!.State);
        Assert.Equal(time.GetUtcNow(), helloOnly.FilterEnforcement.LastSeenUtc);

        var current = status.ClientConnected();
        var connected = await adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.True(connected.FirewallServiceRunning);
        Assert.Equal(FirewallCapabilityStatus.Available, connected.Status);
        Assert.True(connected.FilterEnforcement!.Connected);

        status.ClientDisconnected(current);
        var dropped = await adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.False(dropped.FirewallServiceRunning);
        Assert.Equal(FirewallCapabilityStatus.Degraded, dropped.Status);
        Assert.Contains("disconnected (last seen", dropped.Reason, StringComparison.Ordinal);
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
