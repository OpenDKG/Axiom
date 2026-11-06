// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.Linux.ProcFs;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

public sealed class ProcNetTableTests
{
    private const string TcpHeader =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

    [Fact]
    public void Ipv4_addresses_and_ports_are_decoded_from_kernel_byte_order()
    {
        var rows = ProcNetTable.Parse(
            $"{TcpHeader}\n   0: 0100007F:1F90 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 20 4 30 10 -1\n",
            ipv6: false,
            TransportProtocol.Tcp);

        var row = Assert.Single(rows);
        Assert.Equal(IPAddress.Parse("127.0.0.1"), row.LocalAddress);
        Assert.Equal(8080, row.LocalPort);
        Assert.Equal(IPAddress.Parse("8.8.8.8"), row.RemoteAddress);
        Assert.Equal(443, row.RemotePort);
        Assert.Equal("Established", row.State);
        Assert.Equal(4242, row.Inode);
        Assert.Equal(1000, row.SocketUid);
    }

    [Fact]
    public void Ipv6_listener_is_decoded_and_marked_listening()
    {
        var rows = ProcNetTable.Parse(
            $"{TcpHeader}\n   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  0        0 777 1 0000000000000000 100 0 0 10 0\n",
            ipv6: true,
            TransportProtocol.Tcp);

        var row = Assert.Single(rows);
        Assert.Equal(IPAddress.IPv6Loopback, row.LocalAddress);
        Assert.Equal(8080, row.LocalPort);
        Assert.Equal("Listen", row.State);
        Assert.True(ProcNetTable.IsListening(row.State));
    }

    [Fact]
    public void Mapped_ipv6_address_is_decoded()
    {
        var rows = ProcNetTable.Parse(
            $"{TcpHeader}\n   0: 0000000000000000FFFF00000100007F:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000  0        0 9 1 0000000000000000 100 0 0 10 0\n",
            ipv6: true,
            TransportProtocol.Udp);

        var row = Assert.Single(rows);
        Assert.Equal(IPAddress.Parse("::ffff:127.0.0.1"), row.LocalAddress);
        Assert.Equal(53, row.LocalPort);
        Assert.Equal(TransportProtocol.Udp, row.Protocol);
    }

    [Fact]
    public void Malformed_rows_are_skipped_instead_of_guessed()
    {
        var rows = ProcNetTable.Parse(
            $"{TcpHeader}\n" +
            "garbage\n" +
            "0: not-an-address 00000000:0000 01 0 0 0 0 0 1\n" +
            "0: 0100007F:1F90 ZZ 01 0 0 0 0 0 1\n" +
            "0: 0100007F:1F90 00000000:0000 06 0 0 0 0 0 5\n",
            ipv6: false,
            TransportProtocol.Tcp);

        var row = Assert.Single(rows);
        Assert.Equal("TimeWait", row.State);
        Assert.Equal(5, row.Inode);
    }

    [Theory]
    [InlineData(0x01u, "Established")]
    [InlineData(0x06u, "TimeWait")]
    [InlineData(0x0Au, "Listen")]
    [InlineData(0x0Cu, "NewSynReceived")]
    [InlineData(0x99u, "State 0x99")]
    public void State_names_are_stable(uint value, string expected) =>
        Assert.Equal(expected, ProcNetTable.StateName(value));
}
