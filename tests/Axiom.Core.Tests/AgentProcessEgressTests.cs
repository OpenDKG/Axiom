// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Core.Enforcement;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class AgentProcessEgressTests
{
    private const string Sid = "S-1-5-21-100-200-300-1001";

    [Fact]
    public void An_authorized_agent_executable_gets_an_any_destination_block()
    {
        // Native path per OS: Windows-style rule paths are rejected off Windows (#441).
        var dropper = OperatingSystem.IsWindows() ? @"C:\Users\lab\Downloads\dropper.exe" : "/home/lab/Downloads/dropper";
        var result = AgentFirewallRulePlanner.BuildProcessEgressBlockSpec(
            dropper,
            Sid,
            AgentNetworkPolicyOrigin.ExplicitOperatorApproval,
            explicitlyAuthorizedByUser: true);

        Assert.True(result.IsAllowedToWriteOsRule);
        Assert.NotNull(result.Spec);
        Assert.Equal(FirewallDirection.Outbound, result.Spec!.Direction);
        Assert.Equal(FirewallAction.Block, result.Spec.Action);
        Assert.Equal(NetworkProtocol.Any, result.Spec.Protocol);
        Assert.Empty(result.Spec.RemoteAddresses);
        Assert.Equal(dropper, result.Spec.AppPath);
    }

    [Fact]
    public void Without_explicit_authorization_the_plan_is_rejected()
    {
        var result = AgentFirewallRulePlanner.BuildProcessEgressBlockSpec(
            @"C:\Users\lab\Downloads\dropper.exe",
            Sid,
            AgentNetworkPolicyOrigin.LocalUserPolicy,
            explicitlyAuthorizedByUser: false);

        Assert.False(result.IsAllowedToWriteOsRule);
        Assert.Equal(EnforcementReasonCodes.Disabled, result.RejectionReasonCode);
    }

    [Fact]
    public void A_community_signal_without_authorization_is_advisory_only()
    {
        var result = AgentFirewallRulePlanner.BuildProcessEgressBlockSpec(
            @"C:\Users\lab\Downloads\dropper.exe",
            Sid,
            AgentNetworkPolicyOrigin.CommunitySignal,
            explicitlyAuthorizedByUser: false);

        Assert.False(result.IsAllowedToWriteOsRule);
        Assert.Equal(EnforcementReasonCodes.CommunityAdvisoryOnly, result.RejectionReasonCode);
    }

    [Fact]
    public void Windows_system_binaries_are_refused()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var result = AgentFirewallRulePlanner.BuildProcessEgressBlockSpec(
            Path.Combine(windows, "System32", "svchost.exe"),
            Sid,
            AgentNetworkPolicyOrigin.ExplicitOperatorApproval,
            explicitlyAuthorizedByUser: true);

        Assert.False(result.IsAllowedToWriteOsRule);
        Assert.Contains("Windows system binary", result.RejectionMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Relative_paths_are_refused()
    {
        var result = AgentFirewallRulePlanner.BuildProcessEgressBlockSpec(
            @"dropper.exe",
            Sid,
            AgentNetworkPolicyOrigin.ExplicitOperatorApproval,
            explicitlyAuthorizedByUser: true);

        Assert.False(result.IsAllowedToWriteOsRule);
        Assert.Contains("absolute", result.RejectionMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_missing_caller_sid_is_refused()
    {
        var result = AgentFirewallRulePlanner.BuildProcessEgressBlockSpec(
            @"C:\Users\lab\Downloads\dropper.exe",
            " ",
            AgentNetworkPolicyOrigin.ExplicitOperatorApproval,
            explicitlyAuthorizedByUser: true);

        Assert.False(result.IsAllowedToWriteOsRule);
        Assert.Equal(EnforcementReasonCodes.InvalidRequest, result.RejectionReasonCode);
    }
}
