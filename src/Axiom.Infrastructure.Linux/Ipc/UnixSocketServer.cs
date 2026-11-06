// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Axiom.Contracts.Ipc;

namespace Axiom.Infrastructure.Linux.Ipc;

/// <summary>
/// Local-only Unix domain socket server. The parent directory is private, the socket is 0600 and
/// owned by the allowed user, and the connecting uid is checked with SO_PEERCRED before the first
/// byte is parsed. The protocol, limits and dispatcher are the same as the Windows named pipe.
/// </summary>
public sealed partial class UnixSocketServer : IAsyncDisposable
{
    private const int MaxConcurrentConnections = 16;

    private const UnixFileMode PrivateDirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    private readonly string _socketPath;

    private readonly uint _allowedUid;

    private readonly IpcRequestProcessor _processor;

    private readonly Action<string>? _log;

    private readonly SemaphoreSlim _connections = new(MaxConcurrentConnections, MaxConcurrentConnections);

    private readonly ConcurrentDictionary<int, Task> _handlers = new();

    private Socket? _listener;

    private bool _ownsSocketPath;

    private bool _createdDirectory;

    private int _nextHandlerId;

    public UnixSocketServer(
        string socketPath,
        uint allowedUid,
        IpcRequestProcessor processor,
        Action<string>? log = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(socketPath);
        ArgumentNullException.ThrowIfNull(processor);

        _socketPath = socketPath;
        _allowedUid = allowedUid;
        _processor = processor;
        _log = log;
    }

    public string SocketPath => _socketPath;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            PrepareDirectory();
            _listener = Bind();
            _ownsSocketPath = true;
        }
        catch
        {
            // A half-initialised instance must not leave a listener or a socket it created. A live
            // endpoint owned by another instance is untouched because _ownsSocketPath is false.
            _listener?.Dispose();
            _listener = null;
            CleanupAfterFailedStart();
            throw;
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            Socket accepted;
            try
            {
                accepted = await _listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException exception)
            {
                _log?.Invoke($"Unix socket accept failed: {exception.Message}");
                continue;
            }

            var handlerId = Interlocked.Increment(ref _nextHandlerId);
            var handler = HandleClientAsync(accepted, cancellationToken);
            _handlers[handlerId] = handler;
            _ = handler.ContinueWith(
                completed => _handlers.TryRemove(handlerId, out _),
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _listener?.Dispose();
        _listener = null;

        // Let in-flight handlers observe cancellation before the endpoint is removed. A handler
        // stuck longer than the grace period is left to process shutdown rather than blocking it.
        var handlers = _handlers.Values.ToArray();
        if (handlers.Length > 0)
        {
            try
            {
                await Task.WhenAll(handlers)
                    .WaitAsync(TimeSpan.FromSeconds(5))
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                _log?.Invoke($"Unix socket shutdown left an in-flight handler: {exception.Message}");
            }
        }

        if (_ownsSocketPath)
        {
            DeleteOwnedSocketPath();
            _ownsSocketPath = false;
        }
    }

    private void CleanupAfterFailedStart()
    {
        if (_ownsSocketPath)
        {
            DeleteOwnedSocketPath();
            _ownsSocketPath = false;
        }

        if (!_createdDirectory)
        {
            return;
        }

        var directory = Path.GetDirectoryName(_socketPath);
        if (directory is null || !Directory.Exists(directory))
        {
            return;
        }

        try
        {
            if (!Directory.EnumerateFileSystemEntries(directory).Any())
            {
                Directory.Delete(directory);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Leaving an empty directory is harmless; never fail shutdown over it.
            _ = exception;
        }
    }

    private void PrepareDirectory()
    {
        var directory = Path.GetDirectoryName(_socketPath)
            ?? throw new InvalidOperationException("Socket path has no directory.");

        if (!Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
            File.SetUnixFileMode(directory, PrivateDirectoryMode);
            _createdDirectory = true;
        }
        else
        {
            var info = new DirectoryInfo(directory);
            if (info.LinkTarget is not null)
            {
                throw new IOException($"Refusing to serve from symlinked directory '{directory}'.");
            }

            if (!PosixIdentity.TryGetOwnerUserId(directory, out var owner))
            {
                throw new PlatformNotSupportedException(
                    $"Cannot verify the owner of socket directory '{directory}'.");
            }

            if (owner != PosixIdentity.EffectiveUserId)
            {
                throw new IOException(
                    $"Refusing to use socket directory '{directory}': it is owned by uid {owner}, " +
                    $"not the service uid {PosixIdentity.EffectiveUserId}.");
            }

            // Never chmod a populated shared directory such as /tmp or /run. An empty dedicated
            // directory may be tightened; execute-only (0711) is accepted for the system path.
            var mode = File.GetUnixFileMode(directory);
            const UnixFileMode unsafeBits =
                UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.StickyBit;

            if ((mode & unsafeBits) != 0)
            {
                if (Directory.EnumerateFileSystemEntries(directory).Any())
                {
                    throw new IOException(
                        $"Refusing to use non-private socket directory '{directory}'. " +
                        "Use a dedicated directory with mode 0700 or 0711.");
                }

                File.SetUnixFileMode(directory, PrivateDirectoryMode);
            }
        }

        if (_allowedUid != PosixIdentity.EffectiveUserId &&
            PosixIdentity.EffectiveUserId != 0)
        {
            throw new UnauthorizedAccessException(
                "Only root can expose the socket to a different user; set AXIOM_ALLOWED_UID to the service user.");
        }
    }

    private Socket Bind()
    {
        if (File.Exists(_socketPath))
        {
            var existing = new FileInfo(_socketPath);
            if (existing.LinkTarget is not null)
            {
                throw new IOException($"Refusing to replace symlinked socket '{_socketPath}'.");
            }

            if (IsServiceListening(_socketPath))
            {
                throw new IOException($"Another service is already listening on '{_socketPath}'.");
            }

            File.Delete(_socketPath);
        }

        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        var bound = false;
        try
        {
        socket.Bind(new UnixDomainSocketEndPoint(_socketPath));
        bound = true;

        // The parent directory is still 0700, so the path is not reachable by other users yet.
        File.SetUnixFileMode(_socketPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        if (PosixIdentity.EffectiveUserId == 0)
        {
            try
            {
                if (Chown(_socketPath, _allowedUid, _allowedUid) != 0)
                {
                    if (_allowedUid != PosixIdentity.EffectiveUserId)
                    {
                        throw new IOException(
                            $"Could not hand the socket to uid {_allowedUid}; the configured client " +
                            "would not be able to connect.");
                    }

                    _log?.Invoke($"Could not set socket ownership for uid {_allowedUid}.");
                }
            }
            catch (DllNotFoundException)
            {
                if (_allowedUid != PosixIdentity.EffectiveUserId)
                {
                    throw new PlatformNotSupportedException(
                        "Socket ownership transfer requires a libc chown implementation.");
                }
            }
        }

        if (IsSystemSocketDirectory() || _allowedUid != PosixIdentity.EffectiveUserId)
        {
            // The socket is 0600 and owned by the allowed uid; execute-only traversal lets that
            // user reach it without exposing the directory listing. This also covers a custom
            // AXIOM_IPC_SOCKET path used by a root service for another uid.
            var directory = Path.GetDirectoryName(_socketPath)!;
            File.SetUnixFileMode(
                directory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupExecute | UnixFileMode.OtherExecute);
        }

        socket.Listen(16);
        _log?.Invoke($"Unix socket listening at {_socketPath} for uid {_allowedUid}.");
        return socket;
        }
        catch
        {
            socket.Dispose();
            if (bound)
            {
                DeleteOwnedSocketPath();
            }

            throw;
        }
    }

    private void DeleteOwnedSocketPath()
    {
        try
        {
            if (File.Exists(_socketPath))
            {
                File.Delete(_socketPath);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The parent directory is private; a stale socket is replaced on the next bind.
        }
    }

    private bool IsSystemSocketDirectory() =>
        string.Equals(
            Path.GetDirectoryName(_socketPath),
            Path.GetDirectoryName(IpcEndpoint.SystemSocketPath),
            StringComparison.Ordinal);

    private static bool IsServiceListening(string path)
    {
        using var probe = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            probe.Connect(new UnixDomainSocketEndPoint(path));
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
        finally
        {
            probe.Dispose();
        }
    }

    private async Task HandleClientAsync(Socket accepted, CancellationToken cancellationToken)
    {
        try
        {
            if (!await _connections.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false))
            {
                accepted.Dispose();
                return;
            }
        }
        catch
        {
            accepted.Dispose();
            throw;
        }

        try
        {
            using (accepted)
            {
                if (!TryGetPeerCredentials(accepted, out var uid))
                {
                    _log?.Invoke("Rejected Unix socket client: peer credentials unavailable.");
                    return;
                }

                if (uid != _allowedUid)
                {
                    _log?.Invoke($"Rejected Unix socket client with uid {uid}.");
                    return;
                }

                await using var stream = new NetworkStream(accepted, ownsSocket: false);
                await IpcConnectionHandler
                    .ServeAsync(stream, uid.ToString(System.Globalization.CultureInfo.InvariantCulture), _processor, _log, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (IOException exception)
        {
            _log?.Invoke($"Unix socket client failed: {exception.Message}");
        }
        finally
        {
            _connections.Release();
        }
    }

    internal static bool TryGetPeerCredentials(Socket socket, out uint uid)
    {
        uid = 0;
        var length = Marshal.SizeOf<PeerCredentials>();
        var buffer = Marshal.AllocHGlobal(length);
        try
        {
            // Values are the Linux kernel constants; the managed SocketOptionLevel enum is
            // translated inside .NET and must not be passed to a raw libc call.
            const int SocketLevel = 1;      // SOL_SOCKET
            const int PeerCredentials = 17; // SO_PEERCRED

            if (getsockopt(
                    socket.SafeHandle.DangerousGetHandle(),
                    SocketLevel,
                    PeerCredentials,
                    buffer,
                    ref length) != 0)
            {
                return false;
            }

            var credentials = Marshal.PtrToStructure<PeerCredentials>(buffer);
            uid = credentials.Uid;
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PeerCredentials
    {
        public int Pid;
        public uint Uid;
        public uint Gid;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int getsockopt(
        IntPtr socket,
        int level,
        int optionName,
        IntPtr optionValue,
        ref int optionLength);

    [LibraryImport("libc", EntryPoint = "chown", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Chown(string path, uint owner, uint group);
}
