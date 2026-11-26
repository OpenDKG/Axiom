// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Service.Hosting.Ipc;

/// <summary>
/// When a client last sent a request. Local clients connect for requests rather than staying
/// connected, so "no client" means no request for a while.
/// </summary>
public sealed class ClientActivity
{
    private readonly TimeProvider _time;
    private long _lastTicks;
    private TaskCompletionSource _next = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public ClientActivity(TimeProvider? time = null)
    {
        _time = time ?? TimeProvider.System;
        _lastTicks = _time.GetUtcNow().UtcTicks;
    }

    /// <summary>Completes at the next request. Take it before checking <see cref="IsIdle"/>.</summary>
    public Task NextRequest => Volatile.Read(ref _next).Task;

    /// <summary>True when no request arrived within <paramref name="window"/> (or since start).</summary>
    public bool IsIdle(TimeSpan window) =>
        _time.GetUtcNow().UtcTicks - Interlocked.Read(ref _lastTicks) >= window.Ticks;

    public void Touch()
    {
        Interlocked.Exchange(ref _lastTicks, _time.GetUtcNow().UtcTicks);
        Interlocked.Exchange(ref _next, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously))
            .TrySetResult();
    }
}
