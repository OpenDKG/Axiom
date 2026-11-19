// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers.Binary;
using System.Net;
using System.Text;
using Axiom.Infrastructure.MacOS.Interop;

namespace Axiom.Infrastructure.MacOS.Tests;

/// <summary>
/// Synthetic libproc buffers laid out with the offsets measured on macOS 15.8 x86_64
/// (offsetof() against the SDK headers): socket_fdinfo.psi=24, soi_protocol=156, soi_family=160,
/// soi_kind=232, soi_proto=240, in_sockinfo{fport=0,lport=4,vflag=24,faddr=32,laddr=48,size 80},
/// tcpsi_state=80, proc_bsdinfo size 136 {pid=12, ppid=16, uid=20, comm=48, name=64}.
/// </summary>
public sealed class LibProcLayoutTests
{
    [Fact]
    public void OffsetsMatchTheMacOsHeaders()
    {
        Assert.Equal(24 + 156, LibProcLayout.SoiProtocolOffset);
        Assert.Equal(24 + 160, LibProcLayout.SoiFamilyOffset);
        Assert.Equal(24 + 232, LibProcLayout.SoiKindOffset);
        Assert.Equal(24 + 240, LibProcLayout.InSockInfoOffset);
        Assert.Equal(24 + 240 + 24, LibProcLayout.InsiVflagOffset);
        Assert.Equal(24 + 240 + 80, LibProcLayout.TcpStateOffset);
        Assert.Equal(136, LibProcLayout.BsdInfoSize);
        Assert.True(LibProcLayout.SocketFdInfoBufferSize >= 792);
    }

    [Fact]
    public void DecodesIpv4TcpSocket()
    {
        var buffer = SocketBuffer(
            family: LibProcLayout.AfInet,
            kind: LibProcLayout.SockInfoTcp,
            protocol: LibProcLayout.IpProtoTcp,
            ipv4: true,
            local: IPAddress.Parse("10.0.2.15"),
            localPort: 53122,
            remote: IPAddress.Parse("93.184.215.14"),
            remotePort: 443,
            tcpState: 4);

        var socket = LibProcLayout.ParseSocketFdInfo(1194, buffer);

        Assert.NotNull(socket);
        Assert.Equal(1194, socket.ProcessId);
        Assert.True(socket.Tcp);
        Assert.Equal(IPAddress.Parse("10.0.2.15"), socket.LocalAddress);
        Assert.Equal(53122, socket.LocalPort);
        Assert.Equal(IPAddress.Parse("93.184.215.14"), socket.RemoteAddress);
        Assert.Equal(443, socket.RemotePort);
        Assert.Equal("Established", LibProcLayout.TcpStateName(socket.TcpState));
    }

    [Fact]
    public void DecodesIpv6UdpSocket()
    {
        var buffer = SocketBuffer(
            family: LibProcLayout.AfInet6,
            kind: LibProcLayout.SockInfoIn,
            protocol: LibProcLayout.IpProtoUdp,
            ipv4: false,
            local: IPAddress.Parse("fe80::1"),
            localPort: 5353,
            remote: IPAddress.Parse("2001:db8::53"),
            remotePort: 53,
            tcpState: 0);

        var socket = LibProcLayout.ParseSocketFdInfo(7, buffer);

        Assert.NotNull(socket);
        Assert.False(socket.Tcp);
        Assert.Equal(IPAddress.Parse("2001:db8::53"), socket.RemoteAddress);
        Assert.Equal(53, socket.RemotePort);
        Assert.Equal(5353, socket.LocalPort);
        Assert.Equal(-1, socket.TcpState);
    }

    [Fact]
    public void Ipv4OnIpv6SocketUsesMappedTail()
    {
        // A dual-stack AF_INET6 socket talking IPv4 sets INI_IPV4 and stores the address in the last 4 bytes.
        var buffer = SocketBuffer(LibProcLayout.AfInet6, LibProcLayout.SockInfoTcp, LibProcLayout.IpProtoTcp, true,
            IPAddress.Parse("192.168.1.2"), 1000, IPAddress.Parse("1.1.1.1"), 853, 4);

        var socket = LibProcLayout.ParseSocketFdInfo(1, buffer);

        Assert.Equal(IPAddress.Parse("1.1.1.1"), socket!.RemoteAddress);
    }

    [Fact]
    public void IgnoresUnixAndShortBuffers()
    {
        var unix = SocketBuffer(1, LibProcLayout.SockInfoIn, 0, true, IPAddress.Any, 0, IPAddress.Any, 0, 0);
        Assert.Null(LibProcLayout.ParseSocketFdInfo(1, unix));
        Assert.Null(LibProcLayout.ParseSocketFdInfo(1, new byte[100]));

        var icmp = SocketBuffer(LibProcLayout.AfInet, LibProcLayout.SockInfoIn, 1, true, IPAddress.Any, 0, IPAddress.Any, 0, 0);
        Assert.Null(LibProcLayout.ParseSocketFdInfo(1, icmp));
    }

    [Fact]
    public void DecodesBsdInfo()
    {
        var buffer = new byte[LibProcLayout.BsdInfoSize];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(12), 4321);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(16), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(20), 501);
        Encoding.UTF8.GetBytes("curl").CopyTo(buffer.AsSpan(48));
        Encoding.UTF8.GetBytes("curl-full-name").CopyTo(buffer.AsSpan(64));

        var info = LibProcLayout.ParseBsdInfo(buffer);

        Assert.Equal(new LibProcBsdInfo(4321, 1, 501, "curl", "curl-full-name"), info);
        Assert.Null(LibProcLayout.ParseBsdInfo(new byte[20]));
    }

    [Fact]
    public void ListsOnlySocketDescriptors()
    {
        var buffer = new byte[4 * LibProcLayout.ProcFdInfoSize];
        WriteFd(buffer, 0, fd: 0, type: 1);  // vnode
        WriteFd(buffer, 1, fd: 3, type: 2);  // socket
        WriteFd(buffer, 2, fd: 4, type: 6);  // pipe
        WriteFd(buffer, 3, fd: 9, type: 2);  // socket, beyond the reported length

        Assert.Equal([3], LibProcLayout.SocketDescriptors(buffer, 3 * LibProcLayout.ProcFdInfoSize));
        Assert.Equal([3, 9], LibProcLayout.SocketDescriptors(buffer, buffer.Length));
    }

    [Fact]
    public void PortsAreNetworkOrder()
    {
        // 443 = 0x01BB stored big-endian in the low 16 bits: bytes BB 01 read little-endian = 0xBB01.
        Assert.Equal(443, LibProcLayout.NetworkPort(0xBB01));
        Assert.Equal(53, LibProcLayout.NetworkPort(0x3500));
    }

    private static void WriteFd(byte[] buffer, int index, int fd, uint type)
    {
        BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(index * LibProcLayout.ProcFdInfoSize), fd);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan((index * LibProcLayout.ProcFdInfoSize) + 4), type);
    }

    private static byte[] SocketBuffer(
        int family,
        int kind,
        int protocol,
        bool ipv4,
        IPAddress local,
        int localPort,
        IPAddress remote,
        int remotePort,
        int tcpState)
    {
        var buffer = new byte[792];
        BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(LibProcLayout.SoiProtocolOffset), protocol);
        BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(LibProcLayout.SoiFamilyOffset), family);
        BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(LibProcLayout.SoiKindOffset), kind);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(LibProcLayout.InsiForeignPortOffset), (ushort)remotePort);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(LibProcLayout.InsiLocalPortOffset), (ushort)localPort);
        buffer[LibProcLayout.InsiVflagOffset] = ipv4 ? (byte)0x1 : (byte)0x2;
        WriteAddress(buffer.AsSpan(LibProcLayout.InsiForeignAddressOffset, 16), remote, ipv4);
        WriteAddress(buffer.AsSpan(LibProcLayout.InsiLocalAddressOffset, 16), local, ipv4);
        BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(LibProcLayout.TcpStateOffset), tcpState);
        return buffer;
    }

    private static void WriteAddress(Span<byte> field, IPAddress address, bool ipv4)
    {
        var bytes = address.GetAddressBytes();
        if (ipv4)
        {
            // struct in4in6_addr { u_int32_t i46a_pad32[3]; struct in_addr i46a_addr4; }
            bytes.CopyTo(field[12..]);
        }
        else
        {
            bytes.CopyTo(field);
        }
    }
}
