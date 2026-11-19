// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.Windows.Ipc;

/// <summary>
/// The caller identity of a client of the Windows named pipe. Windows-only by construction: the
/// pipe's DACL admits exactly one user SID and <see cref="PipeServer"/> re-checks the connected
/// client's SID against it before serving, so a client that gets this far is the one user the
/// service was installed for and may use every command class (public read, private read, write).
/// That reasoning does not hold for a Unix socket, where several local users can connect and the
/// transport must decide read and write access per peer; such transports build their
/// <see cref="IpcCaller"/> from the peer credentials and must not use this type.
/// </summary>
public static class WindowsPipeCaller
{
    /// <summary>
    /// Full-access caller for the SID the pipe has already authenticated. <paramref name="sid"/>
    /// becomes the audit-trail actor unchanged.
    /// </summary>
    public static IpcCaller Authenticated(string sid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);
        return new IpcCaller(sid, CanWrite: true, WriteDenialReason: null, CanReadPrivate: true, ReadDenialReason: null);
    }
}
