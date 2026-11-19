// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;

namespace Axiom.Infrastructure.Linux.Nft;

/// <summary>Owner of a local socket: pid and the process executable (realpath), when found.</summary>
public sealed record SocketOwner(int Pid, string? ExePath);

/// <summary>Resolves the process behind a local address/port seen in a trace line; faked in tests.</summary>
public interface ISocketOwnerLookup
{
    SocketOwner? FindOwner(string protocol, string localAddress, int localPort);
}

/// <summary>
/// <c>/proc/net/{tcp,tcp6,udp,udp6}</c> local endpoint → socket inode → <c>/proc/*/fd</c> scan
/// (≈ 8 ms for ~3 000 fds on the evidence box). Used to attribute blocked attempts reported by
/// <c>nft monitor trace</c>; a rejected SYN still has its socket open while <c>connect()</c> fails,
/// so the lookup normally succeeds when run right away.
/// </summary>
public sealed class ProcNetSocketLookup : ISocketOwnerLookup
{
    private readonly string _procRoot;

    public ProcNetSocketLookup(string? procRoot = null)
    {
        _procRoot = string.IsNullOrWhiteSpace(procRoot) ? "/proc" : procRoot;
    }

    [SupportedOSPlatform("linux")]
    public SocketOwner? FindOwner(string protocol, string localAddress, int localPort)
    {
        ArgumentNullException.ThrowIfNull(protocol);
        ArgumentNullException.ThrowIfNull(localAddress);
        if (!IPAddress.TryParse(localAddress, out var address) || protocol is not ("tcp" or "udp"))
        {
            return null;
        }

        var v6 = address.AddressFamily == AddressFamily.InterNetworkV6;
        var file = Path.Combine(_procRoot, "net", protocol + (v6 ? "6" : string.Empty));
        long inode = -1;
        try
        {
            foreach (var line in File.ReadLines(file).Skip(1))
            {
                if (TryParseProcNetLine(line, out var lineAddress, out var linePort, out var lineInode) &&
                    linePort == localPort &&
                    (lineAddress.Equals(address) || lineAddress.Equals(IPAddress.Any) || lineAddress.Equals(IPAddress.IPv6Any)))
                {
                    inode = lineInode;
                    break;
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        if (inode <= 0)
        {
            return null;
        }

        var wanted = string.Create(CultureInfo.InvariantCulture, $"socket:[{inode}]");
        foreach (var dir in SafeEnumerate(_procRoot))
        {
            if (!int.TryParse(Path.GetFileName(dir), out var pid))
            {
                continue;
            }

            foreach (var fd in SafeEnumerate(Path.Combine(dir, "fd")))
            {
                string? target;
                try
                {
                    target = new FileInfo(fd).LinkTarget;
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    continue;
                }

                if (string.Equals(target, wanted, StringComparison.Ordinal))
                {
                    return new SocketOwner(pid, new ProcCgroupFs(procRoot: _procRoot).ReadProcessExe(pid));
                }
            }
        }

        return null;
    }

    /// <summary>Parses one <c>/proc/net/tcp*</c> row: hex little-endian address:port … inode (column 10).</summary>
    public static bool TryParseProcNetLine(string line, out IPAddress localAddress, out int localPort, out long inode)
    {
        ArgumentNullException.ThrowIfNull(line);
        localAddress = IPAddress.None;
        localPort = 0;
        inode = 0;
        var columns = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (columns.Length < 10)
        {
            return false;
        }

        var colon = columns[1].IndexOf(':', StringComparison.Ordinal);
        if (colon < 0 ||
            !int.TryParse(columns[1][(colon + 1)..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out localPort) ||
            !long.TryParse(columns[9], NumberStyles.None, CultureInfo.InvariantCulture, out inode))
        {
            return false;
        }

        var hex = columns[1][..colon];
        if (hex.Length != 8 && hex.Length != 32)
        {
            return false;
        }

        var bytes = Convert.FromHexString(hex);
        // The kernel prints each 32-bit word in host (little-endian) order.
        for (var i = 0; i < bytes.Length; i += 4)
        {
            Array.Reverse(bytes, i, 4);
        }

        localAddress = new IPAddress(bytes);
        return true;
    }

    private static string[] SafeEnumerate(string directory)
    {
        try
        {
            return Directory.EnumerateFileSystemEntries(directory).ToArray();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
