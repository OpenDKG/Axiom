// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using System.Runtime.Versioning;
using Axiom.Infrastructure.Unix.Interop;
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.Unix.Ipc;

/// <summary>
/// The daemon IPC endpoint: a Unix domain socket (default <c>/var/run/axiom/axiom.sock</c>, mode
/// 0666 in a 0755 root directory). It speaks exactly the Windows pipe protocol (newline-delimited
/// JSON envelopes), so .NET <c>NamedPipeClientStream</c> clients connect to the absolute path
/// unchanged. Every accepted peer is authorized by uid before a byte is read. Review #20: besides
/// the global slot limit, every non-root uid may hold at most <see cref="MaxConnectionsPerUid"/>
/// concurrent connections, so one user idling on sockets cannot lock the others (or the desktop
/// app of the installing user) out; root is uncapped.
/// </summary>
[UnsupportedOSPlatform("windows")]
public sealed class UnixSocketIpcTransport : IIpcTransport
{
    public const int MaxConcurrentClients = 16;

    public const int MaxConnectionsPerUid = 4;

    private readonly Dictionary<uint, int> _perUid = [];

    private readonly UnixServicePaths _paths;

    private readonly Func<uint?, PeerDecision> _authorize;

    /// <summary>Connection check only (every console user may write); kept for tests and tools.</summary>
    public UnixSocketIpcTransport(UnixServicePaths paths)
        : this(paths, uid => PeerAuthorization.Decide(uid))
    {
    }

    /// <summary>
    /// Production policy: the owner uid and admin-group switch are re-read from
    /// <paramref name="settings"/> for every connection so an install or a settings change
    /// applies without a daemon restart.
    /// </summary>
    public UnixSocketIpcTransport(UnixServicePaths paths, Axiom.Core.Protection.ProtectionSettingsStore settings)
        : this(paths, uid => PeerAuthorization.Decide(
            uid,
            PeerPolicy.FromSettings(settings.Load(), member => UnixGroups.IsMember(member, PeerPolicy.AdminGroup))))
    {
        ArgumentNullException.ThrowIfNull(settings);
    }

    public UnixSocketIpcTransport(UnixServicePaths paths, Func<uint?, PeerDecision> authorize)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _authorize = authorize ?? throw new ArgumentNullException(nameof(authorize));
    }

    public string Endpoint => _paths.IpcSocketPath;

    /// <summary>
    /// Pure cap decision: root (uid 0) is unlimited; an unknown uid (no peer credentials) and
    /// every other uid get <see cref="MaxConnectionsPerUid"/>.
    /// </summary>
    public static bool IsWithinUidCap(uint? uid, int activeForUid) =>
        uid == 0 || activeForUid < MaxConnectionsPerUid;

    // The startup log must describe the range of the running OS (Linux: uid >= 1000, SO_PEERCRED).
    public string Prepare() => UnixAccountRange.Current.Describe();

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

    private bool TryCountConnection(uint? uid)
    {
        // Peers without credentials share one bucket (uint.MaxValue) so they cannot bypass the cap.
        var key = uid ?? uint.MaxValue;
        lock (_perUid)
        {
            var active = _perUid.GetValueOrDefault(key);
            if (!IsWithinUidCap(uid, active))
            {
                return false;
            }

            _perUid[key] = active + 1;
            return true;
        }
    }

    private void ReleaseConnection(uint? uid)
    {
        var key = uid ?? uint.MaxValue;
        lock (_perUid)
        {
            if (_perUid.TryGetValue(key, out var active))
            {
                if (active <= 1)
                {
                    _perUid.Remove(key);
                }
                else
                {
                    _perUid[key] = active - 1;
                }
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
        uint? uid = null;
        var counted = false;
        try
        {
            uid = UnixPeerCredentials.TryGetPeerUid(client, out var peerUid) ? peerUid : null;
            var decision = _authorize(uid);
            if (!decision.Allowed)
            {
                log($"Rejected IPC client {decision.Actor}: {decision.Reason}");
                client.Dispose();
                return;
            }

            if (!TryCountConnection(uid))
            {
                log($"Rejected IPC client {decision.Actor}: more than {MaxConnectionsPerUid} concurrent connections");
                client.Dispose();
                return;
            }

            counted = true;

            var stream = new NetworkStream(client, ownsSocket: true);
            await using (stream.ConfigureAwait(false))
            {
                var caller = new IpcCaller(decision.Actor, decision.CanWrite, decision.WriteDenialReason);
                await dispatcher.HandleConnectionAsync(stream, caller, cancellationToken).ConfigureAwait(false);
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
            if (counted)
            {
                ReleaseConnection(uid);
            }

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
