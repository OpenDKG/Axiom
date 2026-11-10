// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using System.Runtime.Versioning;
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.MacOS.Ipc;

/// <summary>
/// The daemon IPC endpoint: a Unix domain socket (default <c>/var/run/axiom/axiom.sock</c>, mode
/// 0666 in a 0755 root directory). It speaks exactly the Windows pipe protocol (newline-delimited
/// JSON envelopes), so .NET <c>NamedPipeClientStream</c> clients connect to the absolute path
/// unchanged. Every accepted peer is authorized by uid before a byte is read.
/// </summary>
[UnsupportedOSPlatform("windows")]
public sealed class UnixSocketIpcTransport : IIpcTransport
{
    private const int MaxConcurrentClients = 16;

    private readonly MacServicePaths _paths;

    private readonly Func<uint?, PeerDecision> _authorize;

    public UnixSocketIpcTransport(MacServicePaths paths)
        : this(paths, PeerAuthorization.Decide)
    {
    }

    public UnixSocketIpcTransport(MacServicePaths paths, Func<uint?, PeerDecision> authorize)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _authorize = authorize ?? throw new ArgumentNullException(nameof(authorize));
    }

    public string Endpoint => _paths.IpcSocketPath;

    public string Prepare() => PeerAuthorization.Description;

    public async Task RunAsync(IpcRequestDispatcher dispatcher, Action<string> log, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        ArgumentNullException.ThrowIfNull(log);

        using var slots = new SemaphoreSlim(MaxConcurrentClients, MaxConcurrentClients);

        while (!cancellationToken.IsCancellationRequested)
        {
            Socket listener;
            try
            {
                listener = UnixSocketListener.Create(Endpoint, UnixSocketListener.PublicSocketMode);
            }
            catch (Exception exception) when (exception is
                         SocketException or IOException or UnauthorizedAccessException)
            {
                log($"IPC socket {Endpoint} could not start: {exception.Message}");
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
                continue;
            }

            log($"IPC socket listening on {Endpoint}");

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var client = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
                    if (!slots.Wait(0, CancellationToken.None))
                    {
                        client.Dispose();
                        continue;
                    }

                    _ = ServeAsync(client, dispatcher, log, slots, cancellationToken);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (SocketException exception)
            {
                log($"IPC socket accept failed: {exception.Message}");
            }
            finally
            {
                listener.Dispose();
                UnixSocketListener.TryDelete(Endpoint);
            }
        }
    }

    private async Task ServeAsync(
        Socket client,
        IpcRequestDispatcher dispatcher,
        Action<string> log,
        SemaphoreSlim slots,
        CancellationToken cancellationToken)
    {
        try
        {
            uint? uid = UnixPeerCredentials.TryGetPeerUid(client, out var peerUid) ? peerUid : null;
            var decision = _authorize(uid);
            if (!decision.Allowed)
            {
                log($"Rejected IPC client {decision.Actor}: {decision.Reason}");
                client.Dispose();
                return;
            }

            var stream = new NetworkStream(client, ownsSocket: true);
            await using (stream.ConfigureAwait(false))
            {
                await dispatcher.HandleConnectionAsync(stream, decision.Actor, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception exception) when (exception is
                     IOException or SocketException or ObjectDisposedException or OperationCanceledException)
        {
            // Client went away or the daemon is stopping.
        }
        finally
        {
            client.Dispose();
            try
            {
                slots.Release();
            }
            catch (ObjectDisposedException)
            {
                // The accept loop already ended.
            }
        }
    }
}
