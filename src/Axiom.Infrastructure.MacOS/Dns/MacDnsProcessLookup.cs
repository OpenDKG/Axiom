// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Runtime.Versioning;
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Service.Hosting.Dns;

namespace Axiom.Infrastructure.MacOS.Dns;

/// <summary>
/// DNS query attribution on macOS: the owner of the querying loopback socket is found by scanning
/// the libproc socket table (cached for one second, since a burst of queries shares one scan).
/// Most apps resolve through mDNSResponder, so their queries are attributed to mDNSResponder;
/// tools that query the resolver directly (dig, curl --dns-servers, agents with their own stub)
/// are attributed to themselves.
/// </summary>
[SupportedOSPlatform("macos")]
public sealed class MacDnsProcessLookup : IDnsProcessLookup
{
    private static readonly TimeSpan ScanLifetime = TimeSpan.FromSeconds(1);

    private readonly object _gate = new();

    private IReadOnlyList<LibProcSocket> _sockets = [];

    private DateTimeOffset _scannedUtc = DateTimeOffset.MinValue;

    public int SystemProcessIdLimit => 0;

    public int FindOwningProcess(IPEndPoint source, bool tcp)
    {
        ArgumentNullException.ThrowIfNull(source);

        var match = Find(Scan(false), source, tcp) ?? Find(Scan(true), source, tcp);
        return match?.ProcessId ?? 0;
    }

    public (string Name, string Path) Describe(int processId)
    {
        var path = LibProc.PidPath(processId);
        if (path.Length > 0)
        {
            return (System.IO.Path.GetFileName(path), path);
        }

        return (LibProc.BsdInfo(processId)?.Command ?? string.Empty, string.Empty);
    }

    public int ParentProcessId(int processId) => LibProc.BsdInfo(processId)?.ParentProcessId ?? 0;

    private static LibProcSocket? Find(IReadOnlyList<LibProcSocket> sockets, IPEndPoint source, bool tcp) =>
        sockets.FirstOrDefault(socket =>
            socket.Tcp == tcp &&
            socket.LocalPort == source.Port &&
            (socket.LocalAddress.Equals(source.Address) ||
             socket.LocalAddress.Equals(IPAddress.Any) ||
             socket.LocalAddress.Equals(IPAddress.IPv6Any) ||
             (source.Address.IsIPv4MappedToIPv6 && socket.LocalAddress.Equals(source.Address.MapToIPv4()))));

    private IReadOnlyList<LibProcSocket> Scan(bool force)
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            if (force || now - _scannedUtc > ScanLifetime)
            {
                var sockets = new List<LibProcSocket>();
                foreach (var pid in LibProc.ListPids())
                {
                    sockets.AddRange(LibProc.Sockets(pid));
                }

                _sockets = sockets;
                _scannedUtc = now;
            }

            return _sockets;
        }
    }
}
