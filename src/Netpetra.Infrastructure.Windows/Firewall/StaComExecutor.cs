// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;

namespace Netpetra.Infrastructure.Windows.Firewall;

/// <summary>
/// Runs COM calls on a dedicated STA thread. Windows Firewall COM objects are apartment-threaded
/// and must not be created or used from arbitrary thread-pool threads.
/// </summary>
public sealed class StaComExecutor : IDisposable
{
    private readonly BlockingCollection<Action> _queue = new();
    private readonly Thread _thread;

    public StaComExecutor()
    {
        _thread = new Thread(Run)
        {
            IsBackground = true,
            Name = "Netpetra.FirewallCom",
        };
        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();
    }

    public Task<T> InvokeAsync<T>(Func<T> action, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        cancellationToken.ThrowIfCancellationRequested();

        var completion = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);

        _queue.Add(() =>
        {
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

        return completion.Task.WaitAsync(cancellationToken);
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
