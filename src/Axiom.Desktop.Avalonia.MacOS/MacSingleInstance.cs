// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using System.Text;
using Axiom.Contracts;

namespace Axiom.Desktop.Avalonia.MacOS;

/// <summary>
/// Per-user single instance for the macOS host. The first process holds an exclusive lock on
/// <c>desktop.lock</c> (flock, released by the kernel when the process dies, so a crash never
/// leaves a stale lock) and listens on the Unix socket <c>desktop.sock</c> in the user data
/// directory. A second launch fails to take the lock, connects to the socket, sends <c>show</c>
/// and exits; the first instance then brings its window forward.
/// </summary>
internal sealed class MacSingleInstance : IDisposable
{
    public const string ShowCommand = "show";

    private readonly string _lockPath;
    private readonly string _socketPath;
    private FileStream? _lock;
    private Socket? _listener;
    private CancellationTokenSource? _cancellation;

    public MacSingleInstance(string? directory = null)
    {
        var root = directory ?? AxiomPaths.UserDataDirectory;
        _lockPath = Path.Combine(root, "desktop.lock");
        _socketPath = Path.Combine(root, "desktop.sock");
    }

    public string SocketPath => _socketPath;

    /// <summary>Takes the lock. Returns false when another instance owns it.</summary>
    public bool TryAcquire()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_lockPath)!);

            // FileShare.None maps to flock(LOCK_EX | LOCK_NB) on Unix.
            _lock = new FileStream(_lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            // An unreadable profile must not stop the app; run without single-instance support.
            return true;
        }
    }

    /// <summary>Starts listening for <c>show</c> requests from later launches.</summary>
    public void Listen(Action onShow)
    {
        ArgumentNullException.ThrowIfNull(onShow);
        try
        {
            if (File.Exists(_socketPath))
            {
                // Left over from a crashed instance; we hold the lock, so nobody else uses it.
                File.Delete(_socketPath);
            }

            var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            listener.Bind(new UnixDomainSocketEndPoint(_socketPath));
            listener.Listen(4);
            _listener = listener;
            _cancellation = new CancellationTokenSource();
            _ = AcceptLoopAsync(listener, onShow, _cancellation.Token);
        }
        catch (Exception exception) when (exception is SocketException or IOException or UnauthorizedAccessException)
        {
            StartupLog.Write("single-instance", "Show socket unavailable: " + exception.Message);
        }
    }

    /// <summary>
    /// Delay before the one retry of <see cref="SignalExistingAsync"/>: the first instance holds
    /// the lock a moment before its show socket is bound (review #21).
    /// </summary>
    public static readonly TimeSpan SignalRetryDelay = TimeSpan.FromMilliseconds(300);

    /// <summary>
    /// <see cref="SignalExisting"/> with one retry after <paramref name="retryDelay"/> for the
    /// window between the other instance's TryAcquire and Listen.
    /// </summary>
    public async Task<bool> SignalExistingAsync(TimeSpan retryDelay, CancellationToken cancellationToken = default)
    {
        if (SignalExisting())
        {
            return true;
        }

        await Task.Delay(retryDelay, cancellationToken).ConfigureAwait(false);
        return SignalExisting();
    }

    /// <summary>Asks the running instance to show its window. Returns true on delivery.</summary>
    public bool SignalExisting()
    {
        try
        {
            using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            client.Connect(new UnixDomainSocketEndPoint(_socketPath));
            client.Send(Encoding.ASCII.GetBytes(ShowCommand + "\n"));
            return true;
        }
        catch (Exception exception) when (exception is SocketException or IOException)
        {
            return false;
        }
    }

    private static async Task AcceptLoopAsync(Socket listener, Action onShow, CancellationToken cancellationToken)
    {
        var buffer = new byte[64];
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                using var connection = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
                var read = await connection
                    .ReceiveAsync(buffer, SocketFlags.None, cancellationToken)
                    .ConfigureAwait(false);
                var text = Encoding.ASCII.GetString(buffer, 0, read).Trim();
                if (string.Equals(text, ShowCommand, StringComparison.Ordinal))
                {
                    onShow();
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException)
            {
                // A client that disconnects early is harmless; keep accepting.
            }
        }
    }

    public void Dispose()
    {
        _cancellation?.Cancel();
        _listener?.Dispose();
        _listener = null;
        _cancellation?.Dispose();
        _cancellation = null;
        if (_lock is not null)
        {
            try
            {
                File.Delete(_socketPath);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }

            _lock.Dispose();
            _lock = null;
        }
    }
}
