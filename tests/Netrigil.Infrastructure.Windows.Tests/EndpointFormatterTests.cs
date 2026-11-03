// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Netrigil.Infrastructure.Windows.IpHelper;
using Xunit;

namespace Netrigil.Infrastructure.Windows.Tests;

public sealed class EndpointFormatterTests
{
    [Fact]
    public void Ipv4Bytes_are_read_in_network_order()
    {
        // 127.0.0.1 in the table is stored as 7F 00 00 01; on little-endian that reads 0x0100007F.
        var address = EndpointFormatter.Ipv4Address(0x0100007F);

        Assert.Equal("127.0.0.1", address.ToString());
    }

    [Theory]
    [InlineData(0x0000BB01u, 443)] // 443 stored as 01 BB
    [InlineData(0x00005000u, 80)] // 80 stored as 00 50
    [InlineData(0x00000100u, 1)] // port 1
    public void Ports_are_byte_swapped(uint raw, int expected)
    {
        Assert.Equal((ushort)expected, EndpointFormatter.HostPort(raw));
    }

    [Fact]
    public void Ipv6_endpoint_is_bracketed()
    {
        var address = IPAddress.Parse("::1");

        Assert.Equal("[::1]:443", EndpointFormatter.FormatEndpoint(address, 443));
    }

    [Fact]
    public void Ipv4_endpoint_has_no_brackets()
    {
        var address = IPAddress.Parse("192.0.2.10");

        Assert.Equal("192.0.2.10:80", EndpointFormatter.FormatEndpoint(address, 80));
    }

    [Fact]
    public void Unbound_remote_is_shown_as_unknown()
    {
        Assert.Equal("—", EndpointFormatter.FormatRemote(IPAddress.Any, 0));
        Assert.Equal("—", EndpointFormatter.FormatRemote(IPAddress.IPv6Any, 0));
    }

    [Theory]
    [InlineData(1u, "Closed")]
    [InlineData(2u, "Listen")]
    [InlineData(5u, "Established")]
    [InlineData(11u, "TimeWait")]
    [InlineData(12u, "DeleteTcb")]
    [InlineData(99u, "State 99")]
    public void Tcp_states_are_named(uint state, string expected)
    {
        Assert.Equal(expected, EndpointFormatter.StateName(state));
    }

    [Fact]
    public void Loopback_detection_covers_both_families()
    {
        Assert.True(EndpointFormatter.IsLoopback(IPAddress.Loopback));
        Assert.True(EndpointFormatter.IsLoopback(IPAddress.IPv6Loopback));
        Assert.False(EndpointFormatter.IsLoopback(IPAddress.Parse("192.0.2.10")));
    }
}
