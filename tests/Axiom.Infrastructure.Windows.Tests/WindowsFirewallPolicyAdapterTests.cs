// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Axiom.Infrastructure.Windows.Firewall;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

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
    public async Task Disposing_one_adapter_leaves_other_adapters_usable()
    {
        using var first = new WindowsFirewallPolicyAdapter();
        using var second = new WindowsFirewallPolicyAdapter();

        var reports = await Task.WhenAll(
            first.GetCapabilitiesAsync(CancellationToken.None),
            second.GetCapabilitiesAsync(CancellationToken.None));
        Assert.All(reports, report => Assert.Equal(FirewallCapabilityStatus.Available, report.Status));

        first.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
        {
            _ = first.GetCapabilitiesAsync(CancellationToken.None);
        });
        var remaining = await second.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Equal(FirewallCapabilityStatus.Available, remaining.Status);
        Assert.True(remaining.ManagedRulesReadable);
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
        var spec = new RuleSpec
        {
            ManagedRuleId = Guid.NewGuid(),
            AppPath = Path.Combine(Environment.SystemDirectory, "notepad.exe"),
            Direction = FirewallDirection.Outbound,
            Action = FirewallAction.Block,
            Profiles = FirewallProfile.All,
            CreatedBy = "test",
        };

        var report = await adapter.VerifyAsync(spec, CancellationToken.None);

        Assert.False(report.PresentInOs);
        Assert.False(report.MatchesSpec);
    }

    [Fact]
    public void Reapplying_without_ports_clears_the_old_scope_and_matches()
    {
        var id = Guid.NewGuid();
        var name = OwnedRuleName.Create(id, FirewallDirection.Outbound);
        var spec = new RuleSpec
        {
            ManagedRuleId = id,
            AppPath = @"C:\Program Files\Example\example.exe",
            Direction = FirewallDirection.Outbound,
            Action = FirewallAction.Block,
            Profiles = FirewallProfile.All,
            Protocol = NetworkProtocol.Tcp,
            RemotePorts = "443",
            CreatedBy = "test",
        };
        var rule = new FakeRule
        {
            Name = name,
            ApplicationName = spec.AppPath,
            Direction = 2,
            Action = 0,
            Profiles = (int)FirewallProfile.All,
            Protocol = 6,
            RemoteAddresses = "*",
            RemotePorts = "443",
            Enabled = true,
        };

        Assert.True(WindowsFirewallPolicyAdapter.MatchesSpec(rule, spec));

        var anyPort = spec with { RemotePorts = null };
        Assert.False(WindowsFirewallPolicyAdapter.MatchesSpec(rule, anyPort));

        WindowsFirewallPolicyAdapter.ApplyFields(rule, anyPort, name);

        Assert.Equal("*", rule.RemotePorts);
        Assert.True(WindowsFirewallPolicyAdapter.MatchesSpec(rule, anyPort));
    }

    [Theory]
    [InlineData("1.0.0.0/8", "1.0.0.0/8")]
    [InlineData("1.0.0.0/255.0.0.0", "1.0.0.0/8")]
    [InlineData("2001:db8::/32", "2001:db8::/32")]
    [InlineData("2001:db8::/ffff:ffff::", "2001:db8::/32")]
    [InlineData("10.5.4.3", "10.5.4.3")]
    [InlineData("10.5.4.3/255.255.255.255", "10.5.4.3")]
    [InlineData("10.5.4.3/32", "10.5.4.3")]
    [InlineData("2001:db8::1", "2001:db8::1")]
    [InlineData("2001:db8::1/128", "2001:db8::1")]
    public void Address_normalisation_accepts_cidr_and_mask_notation(string input, string expected)
    {
        Assert.Equal(expected, WindowsFirewallPolicyAdapter.NormalizeAddress(input));
    }

    [Fact]
    public void Readback_in_host_mask_notation_still_matches_bare_ipv4_spec()
    {
        var id = Guid.NewGuid();
        var name = OwnedRuleName.Create(id, FirewallDirection.Outbound);
        var spec = new RuleSpec
        {
            ManagedRuleId = id,
            AppPath = @"C:\Program Files\Example\example.exe",
            Direction = FirewallDirection.Outbound,
            Action = FirewallAction.Block,
            Profiles = FirewallProfile.All,
            Protocol = NetworkProtocol.Any,
            RemoteAddresses = ["203.0.113.42", "1.0.0.0/8"],
            CreatedBy = "test",
        };
        var rule = new FakeRule
        {
            Name = name,
            ApplicationName = spec.AppPath,
            Direction = 2,
            Action = 0,
            Profiles = (int)FirewallProfile.All,
            Protocol = 256,
            RemoteAddresses = "203.0.113.42/255.255.255.255,1.0.0.0/255.0.0.0",
            RemotePorts = string.Empty,
            Enabled = true,
        };

        Assert.True(WindowsFirewallPolicyAdapter.MatchesSpec(rule, spec));
    }

    [Fact]
    public void Readback_in_mask_notation_still_matches_the_cidr_spec()
    {
        var id = Guid.NewGuid();
        var name = OwnedRuleName.Create(id, FirewallDirection.Outbound);
        var spec = new RuleSpec
        {
            ManagedRuleId = id,
            AppPath = @"C:\Program Files\Example\example.exe",
            Direction = FirewallDirection.Outbound,
            Action = FirewallAction.Block,
            Profiles = FirewallProfile.All,
            Protocol = NetworkProtocol.Any,
            RemoteAddresses = ["1.0.0.0/8", "128.0.0.0/1"],
            CreatedBy = "test",
        };
        var rule = new FakeRule
        {
            Name = name,
            ApplicationName = spec.AppPath,
            Direction = 2,
            Action = 0,
            Profiles = (int)FirewallProfile.All,
            Protocol = 256,
            RemoteAddresses = "1.0.0.0/255.0.0.0,128.0.0.0/128.0.0.0",
            RemotePorts = string.Empty,
            Enabled = true,
        };

        Assert.True(WindowsFirewallPolicyAdapter.MatchesSpec(rule, spec));
    }

    [Fact]
    public async Task Recovery_removal_is_refused_outside_the_service_or_an_administrator()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var isAdministrator = new System.Security.Principal.WindowsPrincipal(identity)
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        if (isAdministrator || !Environment.UserInteractive)
        {
            // The caller is already authorized; there is no refusal to assert here.
            return;
        }

        using var adapter = new WindowsFirewallPolicyAdapter();

        await Assert.ThrowsAsync<NotSupportedException>(() =>
            adapter.RemoveCapturedOwnedRuleAsync(
                Guid.NewGuid(),
                FirewallDirection.Outbound,
                CancellationToken.None));
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

    public sealed class FakeRule
    {
        public string Name { get; set; } = string.Empty;

        public string? Description { get; set; }

        public string ApplicationName { get; set; } = string.Empty;

        public int Direction { get; set; }

        public int Action { get; set; }

        public int Profiles { get; set; }

        public int Protocol { get; set; }

        public string? RemoteAddresses { get; set; }

        public string? RemotePorts { get; set; }

        public bool Enabled { get; set; }

        public string? Grouping { get; set; }
    }
}
