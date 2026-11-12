// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Service.Hosting.Ipc;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

public sealed class IpcRulePolicyTests
{
    [Fact]
    public void Inbound_allow_is_rejected_over_the_pipe()
    {
        Assert.True(IpcRulePolicy.IsRejected(Spec(FirewallDirection.Inbound, FirewallAction.Allow)));
    }

    [Theory]
    [InlineData(FirewallDirection.Inbound, FirewallAction.Block)]
    [InlineData(FirewallDirection.Outbound, FirewallAction.Allow)]
    [InlineData(FirewallDirection.Outbound, FirewallAction.Block)]
    public void Other_rule_shapes_are_not_rejected(FirewallDirection direction, FirewallAction action)
    {
        Assert.False(IpcRulePolicy.IsRejected(Spec(direction, action)));
    }

    private static RuleSpec Spec(FirewallDirection direction, FirewallAction action) => new()
    {
        ManagedRuleId = Guid.NewGuid(),
        AppPath = @"C:\test.exe",
        Direction = direction,
        Action = action,
        Profiles = FirewallProfile.All,
        Protocol = NetworkProtocol.Any,
        RemoteAddresses = [],
        CreatedBy = "test",
        Description = "test",
    };
}
