// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Infrastructure.Linux.Monitoring;
using Axiom.Infrastructure.Linux.ProcessIdentity;
using Axiom.Service.Hosting.Dns;

namespace Axiom.Infrastructure.Linux.Dns;

/// <summary>
/// Attributes a DNS query's source socket to a process through the shared
/// <see cref="ProcSocketScanner"/> (same contract as the macOS libproc lookup): the cached table
/// first, one bounded refresh on a miss.
/// </summary>
public sealed class LinuxDnsProcessLookup : IDnsProcessLookup
{
    private readonly ProcSocketScanner _scanner;

    private readonly ILinuxProcessIdentitySource _identities;

    public LinuxDnsProcessLookup()
        : this(ProcSocketScanner.Shared, new ProcProcessIdentityResolver())
    {
    }

    public LinuxDnsProcessLookup(ProcSocketScanner scanner, ILinuxProcessIdentitySource identities)
    {
        _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
        _identities = identities ?? throw new ArgumentNullException(nameof(identities));
    }

    public int SystemProcessIdLimit => 0;

    public int FindOwningProcess(IPEndPoint source, bool tcp)
    {
        ArgumentNullException.ThrowIfNull(source);
        var match = Find(_scanner.Current(), source, tcp) ?? Find(_scanner.Refresh(), source, tcp);
        return match?.ProcessId ?? 0;
    }

    public (string Name, string Path) Describe(int processId)
    {
        var identity = _identities.Resolve(processId, null);
        return (identity.DisplayName, identity.Path);
    }

    public int ParentProcessId(int processId) => _identities.Resolve(processId, null).ParentProcessId ?? 0;

    public static ProcSocket? Find(IReadOnlyList<ProcSocket> sockets, IPEndPoint source, bool tcp)
    {
        ArgumentNullException.ThrowIfNull(sockets);
        ArgumentNullException.ThrowIfNull(source);
        var address = source.Address.IsIPv4MappedToIPv6 ? source.Address.MapToIPv4() : source.Address;
        return sockets.FirstOrDefault(socket =>
            socket.Tcp == tcp &&
            socket.ProcessId > 0 &&
            socket.LocalPort == source.Port &&
            (socket.LocalAddress.Equals(address) ||
             socket.LocalAddress.Equals(IPAddress.Any) ||
             socket.LocalAddress.Equals(IPAddress.IPv6Any)));
    }
}
