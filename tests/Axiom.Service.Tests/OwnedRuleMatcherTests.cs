// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Monitoring;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class OwnedRuleMatcherTests
{
    [Fact]
    public void Applied_block_rule_matches_path_direction_and_port()
    {
        var rule = Rule(FirewallAction.Block, "443", @"C:\Tools\app.exe");
        var connection = Connection(@"C:\Tools\app.exe", "203.0.113.10:443");

        var status = OwnedRuleMatcher.Evaluate([rule], connection);

        Assert.Equal(ConnectionRuleStatus.BlockedByOwnedRule, status);
    }

    [Fact]
    public void Applied_allow_rule_is_reported_separately_from_default_policy()
    {
        var rule = Rule(FirewallAction.Allow, "443", @"C:\Tools\app.exe");
        var connection = Connection(@"C:\Tools\app.exe", "203.0.113.10:443");

        var status = OwnedRuleMatcher.Evaluate([rule], connection);

        Assert.Equal(ConnectionRuleStatus.AllowedByOwnedRule, status);
    }

    [Fact]
    public void Different_path_or_port_has_no_owned_rule()
    {
        var rule = Rule(FirewallAction.Block, "8443", @"C:\Tools\other.exe");
        var connection = Connection(@"C:\Tools\app.exe", "203.0.113.10:443");

        var status = OwnedRuleMatcher.Evaluate([rule], connection);

        Assert.Equal(ConnectionRuleStatus.NoOwnedRule, status);
    }

    [Fact]
    public void Disabled_or_pending_rule_is_not_used()
    {
        var rule = Rule(FirewallAction.Block, "443", @"C:\Tools\app.exe") with
        {
            State = RuleState.Pending,
        };
        var connection = Connection(@"C:\Tools\app.exe", "203.0.113.10:443");

        var status = OwnedRuleMatcher.Evaluate([rule], connection);

        Assert.Equal(ConnectionRuleStatus.NoOwnedRule, status);
    }

    private static ManagedRule Rule(FirewallAction action, string ports, string path) => new()
    {
        ManagedRuleId = Guid.NewGuid(),
        OsRuleName = "Axiom::test::OUT",
        State = RuleState.Applied,
        Spec = new RuleSpec
        {
            ManagedRuleId = Guid.NewGuid(),
            AppPath = path,
            Direction = FirewallDirection.Outbound,
            Action = action,
            Protocol = NetworkProtocol.Tcp,
            RemotePorts = ports,
            Enabled = true,
            CreatedBy = "test",
        },
    };

    private static LiveConnection Connection(string path, string remote) => new()
    {
        AppDisplayName = System.IO.Path.GetFileName(path),
        AppPath = path,
        ProcessId = 42,
        Protocol = TransportProtocol.Tcp,
        LocalEndpoint = "192.0.2.10:50000",
        RemoteEndpoint = remote,
        State = "Established",
        Direction = ConnectionDirection.Outbound,
        InterfaceName = string.Empty,
        FirstObservedUtc = DateTimeOffset.UtcNow,
        Quality = DataQuality.Observed,
    };
}
