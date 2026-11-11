// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Modules;
using Axiom.Infrastructure.Windows.IpHelper;
using Axiom.Infrastructure.Windows.ProcessIdentity;

namespace Axiom.Infrastructure.Windows.Modules;

/// <summary>
/// Reads the owner of a listening loopback port from the IP Helper tables and resolves it with the
/// existing, non-elevated process identity resolver. Read-only: it never opens the target process
/// for writing and never requests elevation. Protected or inaccessible processes resolve to
/// <c>null</c>, which callers must treat as unverified rather than trusted.
/// </summary>
public sealed class WindowsLoopbackListenerInspector : ILoopbackListenerInspector
{
    private readonly ProcessIdentityResolver _identities;

    public WindowsLoopbackListenerInspector()
        : this(new ProcessIdentityResolver())
    {
    }

    public WindowsLoopbackListenerInspector(ProcessIdentityResolver identities)
    {
        ArgumentNullException.ThrowIfNull(identities);
        _identities = identities;
    }

    public ModuleListenerOwner? FindOwner(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        var processId = FindListeningProcessId(endpoint.Port);
        if (processId <= 0)
        {
            return null;
        }

        var identity = _identities.Resolve(processId);
        return identity.IsResolved
            ? new ModuleListenerOwner(
                processId,
                identity.DisplayName,
                identity.ExecutablePath,
                identity.CommandLine)
            : null;
    }

    private static int FindListeningProcessId(int port)
    {
        foreach (var row in NativeMethods.QueryTcpV4())
        {
            if (EndpointFormatter.IsListening(row.State)
                && EndpointFormatter.HostPort(row.LocalPort) == port
                && row.OwningPid != 0
                && EndpointFormatter.IsLoopback(EndpointFormatter.Ipv4Address(row.LocalAddress)))
            {
                return (int)row.OwningPid;
            }
        }

        foreach (var row in NativeMethods.QueryTcpV6())
        {
            if (EndpointFormatter.IsListening(row.State)
                && EndpointFormatter.HostPort(row.LocalPort) == port
                && row.OwningPid != 0
                && EndpointFormatter.IsLoopback(
                    EndpointFormatter.Ipv6Address(row.LocalAddress, row.LocalScopeId)))
            {
                return (int)row.OwningPid;
            }
        }

        // A module may bind the wildcard address; the same port still identifies the owner.
        foreach (var row in NativeMethods.QueryTcpV4())
        {
            if (EndpointFormatter.IsListening(row.State)
                && EndpointFormatter.HostPort(row.LocalPort) == port
                && row.OwningPid != 0)
            {
                return (int)row.OwningPid;
            }
        }

        foreach (var row in NativeMethods.QueryTcpV6())
        {
            if (EndpointFormatter.IsListening(row.State)
                && EndpointFormatter.HostPort(row.LocalPort) == port
                && row.OwningPid != 0)
            {
                return (int)row.OwningPid;
            }
        }

        return 0;
    }
}
