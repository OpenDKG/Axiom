// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.Windows.Ipc;

/// <summary>
/// Windows IPC transport: the ACL-protected named pipe with the client-SID check of
/// <see cref="PipeServer"/>. The allowed SID is resolved once, when the service worker starts,
/// exactly as before the transport seam existed.
/// </summary>
public sealed class NamedPipeIpcTransport(string pipeName, Func<string> resolveAllowedSid) : IIpcTransport
{
    private string? _allowedSid;

    public string Endpoint { get; } = pipeName;

    public string Prepare() => _allowedSid ??= resolveAllowedSid();

    public Task RunAsync(IpcRequestDispatcher dispatcher, Action<string> log, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        var server = new PipeServer(Endpoint, Prepare(), dispatcher, log);
        return server.RunAsync(cancellationToken);
    }
}
