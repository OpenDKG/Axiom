// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Infrastructure.Linux.Firewall;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

public sealed class LinuxFirewallPolicyAdapterTests
{
    [Fact]
    public async Task Capability_reports_a_specific_reason_when_the_object_cannot_load()
    {
        var adapter = new LinuxFirewallPolicyAdapter(
            "/tmp/does-not-exist-cgroup",
            () => false,
            [0x00, 0x01, 0x02, 0x03]);

        var report = await adapter.GetCapabilitiesAsync(CancellationToken.None);

        Assert.Equal(FirewallCapabilityStatus.Unavailable, report.Status);
        Assert.False(string.IsNullOrWhiteSpace(report.Reason));
        Assert.False(report.ManagedRulesReadable);
        Assert.Equal(0, report.ManagedRuleCount);
    }

    [Fact]
    public async Task Capability_never_throws_and_explains_a_closed_write_gate()
    {
        if (LiveFirewallEnvironment.SkipReason is not null)
        {
            return; // No kernel BTF/CAP_BPF on this host; the unavailable path is covered above.
        }

        using var adapter = new LinuxFirewallPolicyAdapter(
            "/tmp/does-not-exist-cgroup",
            () => false);

        var report = await adapter.GetCapabilitiesAsync(CancellationToken.None);

        Assert.Equal(FirewallCapabilityStatus.Available, report.Status);
        Assert.Contains("writes are disabled", report.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.True(report.ManagedRulesReadable);
    }

    [Fact]
    public async Task Apply_is_refused_when_the_write_gate_is_closed()
    {
        using var adapter = new LinuxFirewallPolicyAdapter(
            "/tmp/does-not-exist-cgroup",
            () => false,
            [0x00]);

        await Assert.ThrowsAsync<NotSupportedException>(
            () => adapter.UpsertOwnedRuleAsync(Spec(FirewallAction.Block), CancellationToken.None));
    }

    [Fact]
    public async Task Unsupported_spec_is_rejected_before_the_kernel_is_touched()
    {
        using var adapter = new LinuxFirewallPolicyAdapter(
            "/tmp/does-not-exist-cgroup",
            () => true,
            [0x00]);

        var result = await adapter.UpsertOwnedRuleAsync(
            Spec(FirewallAction.Allow) with { Direction = FirewallDirection.Inbound, RemotePorts = "22" },
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("rule.scope.unsupported_platform", result.ErrorCode);
        Assert.Contains("bind hook", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Restore_keeps_desired_rules_visible_when_enforcement_is_closed()
    {
        using var adapter = new LinuxFirewallPolicyAdapter(
            "/tmp/does-not-exist-cgroup",
            () => false,
            [0x00]);

        var spec = Spec(FirewallAction.Block);
        await adapter.RestoreAsync([spec], CancellationToken.None);

        var rules = await adapter.ListOwnedRulesAsync(CancellationToken.None);
        var rule = Assert.Single(rules);
        Assert.Equal(spec.ManagedRuleId, rule.ManagedRuleId);
        Assert.Equal(RuleState.Desired, rule.State);
    }

    [Fact]
    public async Task Verify_never_claims_enforcement_without_an_attached_policy()
    {
        using var adapter = new LinuxFirewallPolicyAdapter(
            "/tmp/does-not-exist-cgroup",
            () => false,
            [0x00]);

        var report = await adapter.VerifyAsync(Spec(FirewallAction.Block), CancellationToken.None);

        Assert.False(report.PresentInOs);
        Assert.False(report.MatchesSpec);
        Assert.Null(report.EffectiveAction);
        Assert.NotEmpty(report.Notes);
    }

    [Fact]
    public void Write_gate_requires_both_variables()
    {
        var previousEnable = Environment.GetEnvironmentVariable(LinuxFirewallPolicyAdapter.WriteEnableVariable);
        var previousConfirm = Environment.GetEnvironmentVariable(LinuxFirewallPolicyAdapter.WriteConfirmVariable);
        try
        {
            Environment.SetEnvironmentVariable(LinuxFirewallPolicyAdapter.WriteEnableVariable, "1");
            Environment.SetEnvironmentVariable(LinuxFirewallPolicyAdapter.WriteConfirmVariable, null);
            Assert.False(LinuxFirewallPolicyAdapter.IsWriteGateOpen);

            Environment.SetEnvironmentVariable(LinuxFirewallPolicyAdapter.WriteEnableVariable, null);
            Environment.SetEnvironmentVariable(LinuxFirewallPolicyAdapter.WriteConfirmVariable, "yes");
            Assert.False(LinuxFirewallPolicyAdapter.IsWriteGateOpen);

            Environment.SetEnvironmentVariable(LinuxFirewallPolicyAdapter.WriteEnableVariable, "1");
            Environment.SetEnvironmentVariable(LinuxFirewallPolicyAdapter.WriteConfirmVariable, "YES");
            Assert.True(LinuxFirewallPolicyAdapter.IsWriteGateOpen);
        }
        finally
        {
            Environment.SetEnvironmentVariable(LinuxFirewallPolicyAdapter.WriteEnableVariable, previousEnable);
            Environment.SetEnvironmentVariable(LinuxFirewallPolicyAdapter.WriteConfirmVariable, previousConfirm);
        }
    }

    private static RuleSpec Spec(FirewallAction action) => new()
    {
        ManagedRuleId = Guid.Parse("11111111-2222-3333-4444-555555555555"),
        AppPath = TestBinaries.ExistingExecutable(),
        Direction = FirewallDirection.Outbound,
        Action = action,
        Profiles = FirewallProfile.All,
        Protocol = NetworkProtocol.Tcp,
        RemotePorts = "443",
        CreatedBy = PosixIdentity.EffectiveUserId.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };
}
