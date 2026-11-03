// SPDX-License-Identifier: GPL-3.0-or-later
using Netrigil.Contracts.Firewall;
using Netrigil.Core.Firewall;
using Netrigil.Infrastructure.Windows.Firewall;
using Xunit;

namespace Netrigil.Infrastructure.Windows.Tests;

/// <summary>
/// Read-only checks against the real Windows Firewall COM objects. Write methods are only tested
/// for their safety gate; no rule is created or removed on the host.
/// </summary>
public sealed class WindowsFirewallPolicyAdapterTests
{
    [Fact]
    public async Task Capabilities_are_available()
    {
        using var adapter = new WindowsFirewallPolicyAdapter();

        var report = await adapter.GetCapabilitiesAsync(CancellationToken.None);

        Assert.Equal(FirewallCapabilityStatus.Available, report.Status);
        Assert.True(report.ManagedRulesReadable);
    }

    [Fact]
    public async Task Owned_rules_all_follow_the_naming_contract()
    {
        using var adapter = new WindowsFirewallPolicyAdapter();

        var rules = await adapter.ListOwnedRulesAsync(CancellationToken.None);

        Assert.All(rules, rule =>
        {
            Assert.True(OwnedRuleName.IsOwned(rule.OsRuleName));
            Assert.True(OwnedRuleName.TryParse(rule.OsRuleName, out var id, out var direction));
            Assert.Equal(rule.ManagedRuleId, id);
            Assert.Equal(rule.Spec.Direction, direction);
        });
    }

    [Fact]
    public async Task Unknown_rule_is_reported_as_absent()
    {
        using var adapter = new WindowsFirewallPolicyAdapter();

        var report = await adapter.VerifyAsync(Guid.NewGuid(), CancellationToken.None);

        Assert.False(report.PresentInOs);
        Assert.False(report.MatchesSpec);
    }

    [Fact]
    public async Task Writes_are_refused_without_the_explicit_gate()
    {
        var previousEnable = Environment.GetEnvironmentVariable(WindowsFirewallPolicyAdapter.WriteEnableVariable);
        var previousConfirm = Environment.GetEnvironmentVariable(WindowsFirewallPolicyAdapter.WriteConfirmVariable);
        Environment.SetEnvironmentVariable(WindowsFirewallPolicyAdapter.WriteEnableVariable, null);
        Environment.SetEnvironmentVariable(WindowsFirewallPolicyAdapter.WriteConfirmVariable, null);

        try
        {
            using var adapter = new WindowsFirewallPolicyAdapter();
            var spec = new RuleSpec
            {
                ManagedRuleId = Guid.NewGuid(),
                AppPath = Path.Combine(Environment.SystemDirectory, "notepad.exe"),
                Direction = FirewallDirection.Outbound,
                Action = FirewallAction.Block,
                Profiles = FirewallProfile.All,
                CreatedBy = "test",
            };

            await Assert.ThrowsAsync<NotSupportedException>(() =>
                adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None));

            var rules = await adapter.ListOwnedRulesAsync(CancellationToken.None);
            Assert.DoesNotContain(rules, rule => rule.ManagedRuleId == spec.ManagedRuleId);
        }
        finally
        {
            Environment.SetEnvironmentVariable(WindowsFirewallPolicyAdapter.WriteEnableVariable, previousEnable);
            Environment.SetEnvironmentVariable(WindowsFirewallPolicyAdapter.WriteConfirmVariable, previousConfirm);
        }
    }
}
