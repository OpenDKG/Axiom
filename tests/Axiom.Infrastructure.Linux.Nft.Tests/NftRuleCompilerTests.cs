// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Nft;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

public sealed class NftRuleCompilerTests
{
    private static readonly Guid Id1 = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");
    private static readonly Guid Id2 = Guid.Parse("7c9e6679-7425-40de-944b-e07fc1f90ae7");

    private sealed class StaticCgroups(Func<string, string?> resolve) : IAppCgroupResolver
    {
        public bool TryResolve(string appPath, out string cgroupPath, out string reason)
        {
            cgroupPath = resolve(appPath) ?? string.Empty;
            reason = cgroupPath.Length == 0 ? $"appPath is not reachable on this system: {appPath}" : string.Empty;
            return cgroupPath.Length > 0;
        }
    }

    private static readonly IAppCgroupResolver Curl = new StaticCgroups(app => app == "/usr/bin/curl" ? "axiom.slice/a-0011223344556677" : null);

    [Fact]
    public void Block_rule_becomes_reject_for_tcp_and_drop_for_the_rest_keyed_on_the_cgroup()
    {
        var compilation = NftRuleCompiler.Compile([Specs.Block("/usr/bin/curl", Id1)], 7, Curl);

        Assert.Empty(compilation.Rejected);
        var rule = Assert.Single(compilation.Applied);
        Assert.Equal("axiom.slice/a-0011223344556677", rule.CgroupPath);
        Assert.Equal(
            [
                "meta l4proto tcp socket cgroupv2 level 2 \"axiom.slice/a-0011223344556677\" counter meta nftrace set 1 reject with tcp reset comment \"axiom:0f8fad5b-d9cb-469f-a165-70867728950e:1\"",
                "meta l4proto udp socket cgroupv2 level 2 \"axiom.slice/a-0011223344556677\" counter meta nftrace set 1 drop comment \"axiom:0f8fad5b-d9cb-469f-a165-70867728950e:2\"",
                "meta l4proto != { tcp, udp } socket cgroupv2 level 2 \"axiom.slice/a-0011223344556677\" counter meta nftrace set 1 drop comment \"axiom:0f8fad5b-d9cb-469f-a165-70867728950e:3\"",
            ],
            rule.Lines);
        Assert.StartsWith("add table inet axiom\ndelete table inet axiom\ntable inet axiom {\n\tcomment \"axiom generation 7\"\n", compilation.Script, StringComparison.Ordinal);
        Assert.Contains("chain axiom_out {\n\t\ttype filter hook output priority filter; policy accept;\n", compilation.Script, StringComparison.Ordinal);
        Assert.Contains("chain axiom_in {\n\t\ttype filter hook input priority filter; policy accept;\n", compilation.Script, StringComparison.Ordinal);
    }

    [Fact]
    public void Addresses_and_ports_split_by_family_and_protocol()
    {
        var spec = Specs.Block("/usr/bin/curl", Id1) with
        {
            RemoteAddresses = ["1.2.3.4", "10.1.2.3/8", "2001:db8::/32", "1.2.3.4-1.2.3.9", " "],
            RemotePorts = "443, 8000-8100,53",
        };

        var compilation = NftRuleCompiler.Compile([spec], 1, Curl);

        var lines = Assert.Single(compilation.Applied).Lines;
        Assert.Equal(4, lines.Count);
        Assert.Contains("meta l4proto tcp socket cgroupv2 level 2 \"axiom.slice/a-0011223344556677\" ip daddr { 1.2.3.4, 10.0.0.0/8, 1.2.3.4-1.2.3.9 } tcp dport { 443, 8000-8100, 53 } counter meta nftrace set 1 reject with tcp reset comment \"axiom:0f8fad5b-d9cb-469f-a165-70867728950e:1\"", lines);
        Assert.Contains("meta l4proto udp socket cgroupv2 level 2 \"axiom.slice/a-0011223344556677\" ip daddr { 1.2.3.4, 10.0.0.0/8, 1.2.3.4-1.2.3.9 } udp dport { 443, 8000-8100, 53 } counter meta nftrace set 1 drop comment \"axiom:0f8fad5b-d9cb-469f-a165-70867728950e:2\"", lines);
        Assert.Contains("meta l4proto tcp socket cgroupv2 level 2 \"axiom.slice/a-0011223344556677\" ip6 daddr { 2001:db8::/32 } tcp dport { 443, 8000-8100, 53 } counter meta nftrace set 1 reject with tcp reset comment \"axiom:0f8fad5b-d9cb-469f-a165-70867728950e:3\"", lines);
        Assert.DoesNotContain(lines, line => line.Contains("!= { tcp, udp }", StringComparison.Ordinal));
    }

    [Fact]
    public void Block_rules_precede_allow_rules_and_inbound_uses_source_fields()
    {
        var allow = Specs.Allow("/usr/bin/curl", Id1) with { Protocol = NetworkProtocol.Tcp, RemotePorts = "80" };
        var block = Specs.Block("/usr/bin/curl", Id2) with { Protocol = NetworkProtocol.Udp };
        var inbound = Specs.Block("/usr/bin/curl", Guid.Parse("11111111-1111-1111-1111-111111111111"), FirewallDirection.Inbound) with
        {
            RemoteAddresses = ["10.0.0.0/8"],
            RemotePorts = "1024-65535",
            Protocol = NetworkProtocol.Tcp,
        };

        var script = NftRuleCompiler.Compile([allow, block, inbound], 1, Curl).Script;

        var blockAt = script.IndexOf("axiom:7c9e6679", StringComparison.Ordinal);
        var allowAt = script.IndexOf("axiom:0f8fad5b", StringComparison.Ordinal);
        var guardAt = script.IndexOf("ip daddr 127.0.0.0/8 accept", StringComparison.Ordinal);
        Assert.True(guardAt < blockAt && blockAt < allowAt, script);
        Assert.Contains("meta l4proto tcp socket cgroupv2 level 2 \"axiom.slice/a-0011223344556677\" tcp dport { 80 } counter accept comment", script, StringComparison.Ordinal);
        Assert.Contains("\tchain axiom_in {\n\t\ttype filter hook input priority filter; policy accept;\n\t\tip saddr 127.0.0.0/8 accept\n\t\tip6 saddr ::1 accept\n\t\tmeta l4proto tcp socket cgroupv2 level 2 \"axiom.slice/a-0011223344556677\" ip saddr { 10.0.0.0/8 } tcp sport { 1024-65535 } counter meta nftrace set 1 reject with tcp reset comment \"axiom:11111111-1111-1111-1111-111111111111:1\"\n\t}\n", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Loopback_part_of_a_rule_is_emitted_above_the_loopback_guard()
    {
        var spec = Specs.Block("/usr/bin/curl", Id1) with { RemoteAddresses = ["127.0.0.1", "8.8.8.8", "::1"], Protocol = NetworkProtocol.Tcp };

        var script = NftRuleCompiler.Compile([spec], 1, Curl).Script;

        var guard = script.IndexOf("\t\tip daddr 127.0.0.0/8 accept", StringComparison.Ordinal);
        var loopback4 = script.IndexOf("ip daddr { 127.0.0.1 } counter", StringComparison.Ordinal);
        var loopback6 = script.IndexOf("ip6 daddr ::1 counter", StringComparison.Ordinal);
        var normal = script.IndexOf("ip daddr { 8.8.8.8 } counter", StringComparison.Ordinal);
        Assert.True(loopback4 > 0 && loopback4 < guard, script);
        Assert.True(loopback6 > 0 && loopback6 < guard, script);
        Assert.True(normal > guard, script);
    }

    [Theory]
    [InlineData("1.2.3", "invalid address '1.2.3'")]
    [InlineData("example.com", "invalid address 'example.com'")]
    [InlineData("LocalSubnet", "Windows-only")]
    [InlineData("10.0.0.0/33", "invalid address '10.0.0.0/33'")]
    [InlineData("1.2.3.9-1.2.3.4", "invalid address '1.2.3.9-1.2.3.4'")]
    [InlineData("fe80::1%eth0", "invalid address")]
    public void Unsupported_addresses_reject_the_rule(string address, string reason)
    {
        var compilation = NftRuleCompiler.Compile([Specs.Block("/usr/bin/curl", Id1) with { RemoteAddresses = [address] }], 1, Curl);

        Assert.Empty(compilation.Applied);
        var rejected = Assert.Single(compilation.Rejected);
        Assert.Equal(Id1, rejected.RuleId);
        Assert.Contains(reason, rejected.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain("axiom:0f8fad5b", compilation.Script, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("RPC", "invalid port 'RPC'")]
    [InlineData("70000", "invalid port '70000'")]
    [InlineData("90-80", "invalid port range '90-80'")]
    [InlineData(",", "no port")]
    public void Unsupported_ports_reject_the_rule(string ports, string reason)
    {
        var compilation = NftRuleCompiler.Compile([Specs.Block("/usr/bin/curl", Id1) with { RemotePorts = ports }], 1, Curl);

        var rejected = Assert.Single(compilation.Rejected);
        Assert.Contains(reason, rejected.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Unreachable_relative_wildcard_or_profile_less_rules_are_rejected_and_disabled_rules_skipped()
    {
        var specs = new[]
        {
            Specs.Block("/opt/missing/app", Id1),
            Specs.Block("relative/app", Id2),
            Specs.Block("*", Guid.Parse("22222222-2222-2222-2222-222222222222")),
            Specs.Block("/usr/bin/curl", Guid.Parse("33333333-3333-3333-3333-333333333333")) with { Profiles = FirewallProfile.None },
            Specs.Block("/usr/bin/curl", Guid.Parse("44444444-4444-4444-4444-444444444444")) with { Enabled = false },
        };

        var compilation = NftRuleCompiler.Compile(specs, 1, Curl);

        Assert.Empty(compilation.Applied);
        Assert.Equal(4, compilation.Rejected.Count);
        Assert.Contains(compilation.Rejected, r => r.RuleId == Id1 && r.Reason.Contains("not reachable", StringComparison.Ordinal));
        Assert.Contains(compilation.Rejected, r => r.RuleId == Id2 && r.Reason.Contains("not absolute", StringComparison.Ordinal));
        Assert.Contains(compilation.Rejected, r => r.Reason.Contains("appPath is empty", StringComparison.Ordinal));
        Assert.Contains(compilation.Rejected, r => r.Reason.Contains("profiles is None", StringComparison.Ordinal));
    }

    [Fact]
    public void Star_address_and_zero_prefix_mean_any_and_do_not_name_loopback()
    {
        var spec = Specs.Allow("/usr/bin/curl", Id1) with { RemoteAddresses = ["*"], Protocol = NetworkProtocol.Tcp };
        var any = NftRuleCompiler.Compile([spec], 1, Curl);
        Assert.Equal("meta l4proto tcp socket cgroupv2 level 2 \"axiom.slice/a-0011223344556677\" counter accept comment \"axiom:0f8fad5b-d9cb-469f-a165-70867728950e:1\"", Assert.Single(Assert.Single(any.Applied).Lines));

        var zero = NftRuleCompiler.Compile([spec with { RemoteAddresses = ["0.0.0.0/0", "::/0"] }], 1, Curl);
        var guard = zero.Script.IndexOf("\t\tip daddr 127.0.0.0/8 accept", StringComparison.Ordinal);
        Assert.True(zero.Script.IndexOf("axiom:0f8fad5b", StringComparison.Ordinal) > guard);
        Assert.Contains("ip daddr { 0.0.0.0/0 }", zero.Script, StringComparison.Ordinal);
    }

    [Fact]
    public void Deeper_cgroup_paths_use_their_depth_as_the_level()
    {
        var deep = new StaticCgroups(_ => "user.slice/user-1000.slice/user@1000.service/app.slice/app-x.scope");

        var line = Assert.Single(NftRuleCompiler.Compile([Specs.Allow("/x", Id1) with { Protocol = NetworkProtocol.Tcp }], 1, deep).Applied).Lines[0];

        Assert.Contains("socket cgroupv2 level 5 \"user.slice/user-1000.slice/user@1000.service/app.slice/app-x.scope\"", line, StringComparison.Ordinal);
    }
}
