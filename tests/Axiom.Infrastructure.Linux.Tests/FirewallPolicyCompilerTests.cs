// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Firewall;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

public sealed class FirewallPolicyCompilerTests
{
    private static readonly ExecutableIdentity Identity = new(11, 22, "/usr/bin/tool");

    [Fact]
    public void Outbound_block_expands_ports_and_cidrs_into_slots()
    {
        var spec = Spec(
            FirewallAction.Block,
            FirewallDirection.Outbound,
            NetworkProtocol.Tcp,
            remoteAddresses: ["10.0.0.0/8"],
            remotePorts: "443,8000-8002");

        Assert.True(FirewallPolicyCompiler.TryCompile(Identity, [spec], out var compiled, out var error), error?.Message);

        Assert.NotNull(compiled);
        Assert.Equal(2, compiled.Slots.Count);
        Assert.All(compiled.Slots, slot =>
        {
            Assert.Equal(FirewallAction.Block, slot.Action);
            Assert.Equal(6, slot.Protocol);
            Assert.Equal(4, slot.Family);
            Assert.Equal(8, slot.Prefix);
            Assert.Equal(10, slot.Address[0]);
            Assert.Equal(1, slot.Direction);
        });
        Assert.Contains(compiled.Slots, slot => slot.PortMin == 443 && slot.PortMax == 443);
        Assert.Contains(compiled.Slots, slot => slot.PortMin == 8000 && slot.PortMax == 8002);
    }

    [Fact]
    public void Ipv6_cidr_is_masked()
    {
        var spec = Spec(
            FirewallAction.Block,
            FirewallDirection.Outbound,
            NetworkProtocol.Udp,
            remoteAddresses: ["2001:db8::1/32"]);

        Assert.True(FirewallPolicyCompiler.TryCompile(Identity, [spec], out var compiled, out var error), error?.Message);

        var slot = Assert.Single(compiled!.Slots);
        Assert.Equal(6, slot.Family);
        Assert.Equal(32, slot.Prefix);
        Assert.Equal(new byte[] { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, slot.Address);
    }

    [Fact]
    public void Allow_rule_puts_the_executable_in_allow_list_mode()
    {
        var spec = Spec(FirewallAction.Allow, FirewallDirection.Outbound, NetworkProtocol.Tcp, remotePorts: "443");

        Assert.True(FirewallPolicyCompiler.TryCompile(Identity, [spec], out var compiled, out var error), error?.Message);

        Assert.True(compiled!.AllowOut);
        Assert.False(compiled.AllowIn);
    }

    [Fact]
    public void Inbound_allow_is_refused_instead_of_broadened()
    {
        var spec = Spec(FirewallAction.Allow, FirewallDirection.Inbound, NetworkProtocol.Tcp, remotePorts: "22");

        Assert.False(FirewallPolicyCompiler.TryCompile(Identity, [spec], out _, out var error));
        Assert.Equal("rule.scope.unsupported_platform", error!.Code);
        Assert.Contains("bind hook", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Inbound_remote_addresses_are_refused()
    {
        var spec = Spec(
            FirewallAction.Block,
            FirewallDirection.Inbound,
            NetworkProtocol.Tcp,
            remoteAddresses: ["192.0.2.0/24"]);

        Assert.False(FirewallPolicyCompiler.TryCompile(Identity, [spec], out _, out var error));
        Assert.Equal("rule.scope.unsupported_platform", error!.Code);
    }

    [Fact]
    public void Profile_restricted_rule_is_refused()
    {
        var spec = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Any) with
        {
            Profiles = FirewallProfile.Public,
        };

        Assert.False(FirewallPolicyCompiler.TryCompile(Identity, [spec], out _, out var error));
        Assert.Equal("rule.scope.unsupported_platform", error!.Code);
    }

    [Fact]
    public void Port_list_without_a_protocol_is_refused()
    {
        var spec = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Any, remotePorts: "80,443");

        Assert.False(FirewallPolicyCompiler.TryCompile(Identity, [spec], out _, out var error));
        Assert.Equal("rule.ports.protocol_required", error!.Code);
    }

    [Fact]
    public void Expansion_beyond_the_kernel_slot_limit_is_refused()
    {
        var addresses = Enumerable.Range(0, 5).Select(index => $"10.0.{index}.0/24").ToArray();
        var spec = Spec(
            FirewallAction.Block,
            FirewallDirection.Outbound,
            NetworkProtocol.Tcp,
            remoteAddresses: addresses,
            remotePorts: "80,443,8080,8443");

        Assert.False(FirewallPolicyCompiler.TryCompile(Identity, [spec], out _, out var error));
        Assert.Equal("rule.expansion_limit", error!.Code);
    }

    [Fact]
    public void Disabled_rule_keeps_its_slots_but_does_not_enable_allow_list_mode()
    {
        var spec = Spec(FirewallAction.Allow, FirewallDirection.Outbound, NetworkProtocol.Tcp, remotePorts: "443") with
        {
            Enabled = false,
        };

        Assert.True(FirewallPolicyCompiler.TryCompile(Identity, [spec], out var compiled, out var error), error?.Message);

        Assert.False(compiled!.AllowOut);
        Assert.All(compiled.Slots, slot => Assert.False(slot.Enabled));
    }

    [Fact]
    public void Invalid_ports_and_addresses_are_refused()
    {
        Assert.False(FirewallPolicyCompiler.TryCompile(
            Identity,
            [Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, remotePorts: "0")],
            out _,
            out var portError));
        Assert.Equal("rule.ports.invalid", portError!.Code);

        Assert.False(FirewallPolicyCompiler.TryCompile(
            Identity,
            [Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, remoteAddresses: ["example.com"])],
            out _,
            out var addressError));
        Assert.Equal("rule.addresses.invalid", addressError!.Code);
    }

    private static RuleSpec Spec(
        FirewallAction action,
        FirewallDirection direction,
        NetworkProtocol protocol,
        IReadOnlyList<string>? remoteAddresses = null,
        string? remotePorts = null) => new()
        {
            ManagedRuleId = Guid.NewGuid(),
            AppPath = "/usr/bin/tool",
            Direction = direction,
            Action = action,
            Protocol = protocol,
            RemoteAddresses = remoteAddresses ?? [],
            RemotePorts = remotePorts,
            CreatedBy = "uid:1000",
        };
}
