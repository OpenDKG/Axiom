// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;

namespace Axiom.Infrastructure.Windows.Firewall;

/// <summary>
/// Runs COM calls on a dedicated STA thread. Windows Firewall COM objects are apartment-threaded
/// and must not be created or used from arbitrary thread-pool threads.
/// </summary>
public sealed class StaComExecutor : IDisposable
{
    /// <summary>How long a caller waits for one call, including time spent queued.</summary>
    public static readonly TimeSpan DefaultCallTimeout = TimeSpan.FromSeconds(15);

    private const int Queued = 0;
    private const int Running = 1;
    private const int Abandoned = 2;

    private readonly BlockingCollection<Action> _queue = new();
    private readonly Thread _thread;
    private readonly TimeSpan _callTimeout;

    // A real parameterless constructor: the firewall adapter creates this through Lazy<T>.
    public StaComExecutor()
        : this(DefaultCallTimeout)
    {
    }

    public StaComExecutor(TimeSpan callTimeout)
    {
        _callTimeout = callTimeout;
        _thread = new Thread(Run)
        {
            IsBackground = true,
            Name = "Axiom.FirewallCom",
        };
        if (OperatingSystem.IsWindows())
        {
            _thread.SetApartmentState(ApartmentState.STA);
        }

        _thread.Start();
    }

    public Task<T> InvokeAsync<T>(Func<T> action, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        cancellationToken.ThrowIfCancellationRequested();

        var completion = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);

        var state = new[] { Queued };
        _queue.Add(() =>
        {
            // A caller that stopped waiting was told the call did not run, so it must not run now.
            if (Interlocked.CompareExchange(ref state[0], Running, Queued) != Queued)
            {
                return;
            }

            try
            {
                completion.TrySetResult(action());
            }
#pragma warning disable CA1031 // The COM exception must be surfaced to the awaiting caller.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                completion.TrySetException(exception);
            }
        }, cancellationToken);

        return WaitBoundedAsync(completion.Task, state, cancellationToken);
    }

    private async Task<T> WaitBoundedAsync<T>(Task<T> call, int[] state, CancellationToken cancellationToken)
    {
        try
        {
            return await call.WaitAsync(_callTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException) when (!call.IsCompleted)
        {
            var notStarted = Interlocked.CompareExchange(ref state[0], Abandoned, Queued) == Queued;
            throw new TimeoutException(
                $"Windows Firewall did not answer within {_callTimeout.TotalSeconds:0.#} s. " +
                (notStarted ? "The call was not run." : "The call is still running and may still complete."));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _ = Interlocked.CompareExchange(ref state[0], Abandoned, Queued);
            throw;
        }
    }

    public void Dispose()
    {
        _queue.CompleteAdding();
    }

    private void Run()
    {
        foreach (var action in _queue.GetConsumingEnumerable())
        {
            action();
        }
    }
}
