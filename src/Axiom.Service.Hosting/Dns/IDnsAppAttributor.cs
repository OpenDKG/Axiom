// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;

namespace Axiom.Service.Hosting.Dns;

/// <summary>Querying app (and nearest AI agent ancestor) of a blocked DNS query.</summary>
public sealed record DnsAppIdentity(string Name, string Path, string AgentName, string AgentPath)
{
    public static DnsAppIdentity Unknown { get; } = new(string.Empty, string.Empty, string.Empty, string.Empty);
}

/// <summary>
/// Platform seam: maps the loopback source endpoint of a DNS query to the owning process. Windows
/// uses the IP Helper owner tables, macOS the libproc socket table.
/// </summary>
public interface IDnsAppAttributor
{
    DnsAppIdentity? Resolve(IPEndPoint source, bool tcp);
}
