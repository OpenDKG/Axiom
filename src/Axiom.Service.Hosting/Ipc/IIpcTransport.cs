// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Service.Hosting.Ipc;

/// <summary>
/// Platform transport of the local service endpoint: creates the OS endpoint, authenticates every
/// caller and hands authorized connections to the shared <see cref="IpcRequestDispatcher"/>.
/// </summary>
public interface IIpcTransport
{
    /// <summary>Pipe name (Windows) or socket path (Unix).</summary>
    string Endpoint { get; }

    /// <summary>Resolves who may connect; the returned description is logged at startup.</summary>
    string Prepare();

    /// <summary>Accepts clients until <paramref name="cancellationToken"/> fires.</summary>
    Task RunAsync(IpcRequestDispatcher dispatcher, Action<string> log, CancellationToken cancellationToken);
}
