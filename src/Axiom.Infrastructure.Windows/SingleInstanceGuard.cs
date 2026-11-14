// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.Windows;

/// <summary>
/// Coordinates single-instance startup before the UI framework initializes so a second launch
/// wakes the existing window and exits cleanly without spinning up an Avalonia dispatcher.
/// </summary>
public sealed class SingleInstanceGuard : IDisposable
{
    public const string DefaultMutexName = @"Local\Axiom.Desktop.SingleInstance";
    public const string DefaultShowEventName = @"Local\Axiom.Desktop.Show";

    private readonly Mutex _mutex;
    private readonly EventWaitHandle _showEvent;
    private Thread? _listenerThread;
    private int _disposed;

    private SingleInstanceGuard(Mutex mutex, EventWaitHandle showEvent)
    {
        _mutex = mutex;
        _showEvent = showEvent;
    }

    /// <summary>
    /// Attempts to claim the single-instance mutex and create its wake event. If another instance
    /// already owns the mutex, signals that instance to show its window and returns <see langword="null"/>.
    /// </summary>
    public static SingleInstanceGuard? AcquireOrSignalExisting(
        string mutexName = DefaultMutexName,
        string showEventName = DefaultShowEventName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mutexName);
        ArgumentException.ThrowIfNullOrWhiteSpace(showEventName);

        var mutex = new Mutex(initiallyOwned: true, name: mutexName, createdNew: out var createdNew);
        if (!createdNew)
        {
            mutex.Dispose();
            SignalExisting(showEventName);
            return null;
        }

        try
        {
            var showEvent = new EventWaitHandle(
                initialState: false,
                mode: EventResetMode.AutoReset,
                name: showEventName);
            return new SingleInstanceGuard(mutex, showEvent);
        }
        catch
        {
            mutex.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Starts a background listener that invokes <paramref name="onShowRequested"/> whenever a
    /// subsequent launch signals the existing instance. Safe to call once the main window exists.
    /// </summary>
    public void StartListening(Action onShowRequested)
    {
        ArgumentNullException.ThrowIfNull(onShowRequested);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        if (_listenerThread is not null)
        {
            return;
        }

        _listenerThread = new Thread(() => ListenLoop(onShowRequested))
        {
            IsBackground = true,
            Name = "Axiom show-window signal",
        };
        _listenerThread.Start();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            _showEvent.Set();
        }
        catch (ObjectDisposedException)
        {
        }

        _listenerThread?.Join(TimeSpan.FromMilliseconds(500));
        _showEvent.Dispose();
        _mutex.Dispose();
    }

    private void ListenLoop(Action onShowRequested)
    {
        while (Volatile.Read(ref _disposed) == 0)
        {
            try
            {
                _showEvent.WaitOne();
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            if (Volatile.Read(ref _disposed) != 0)
            {
                return;
            }

            onShowRequested();
        }
    }

    private static void SignalExisting(string showEventName)
    {
        try
        {
            if (EventWaitHandle.TryOpenExisting(showEventName, out var existing))
            {
                using (existing)
                {
                    existing.Set();
                }
            }
        }
        catch (Exception exception) when (exception is
                     UnauthorizedAccessException or IOException or WaitHandleCannotBeOpenedException)
        {
        }
    }
}
