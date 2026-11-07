// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Threading;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.Windows;

public sealed class AvaloniaUiTimerFactory : IUiTimerFactory
{
    public IUiTimer Create(TimeSpan interval) => new AvaloniaUiTimer(interval);
}

public sealed class AvaloniaUiDispatcher : IUiDispatcher
{
    public bool IsUiThread => Dispatcher.UIThread.CheckAccess();

    public void Post(Action action) => Dispatcher.UIThread.Post(action);
}

internal sealed class AvaloniaUiTimer : IUiTimer
{
    private readonly DispatcherTimer _timer;

    public AvaloniaUiTimer(TimeSpan interval)
    {
        _timer = new DispatcherTimer { Interval = interval };
        _timer.Tick += (_, _) => Tick?.Invoke(this, EventArgs.Empty);
    }

    public TimeSpan Interval
    {
        get => _timer.Interval;
        set => _timer.Interval = value;
    }

    public bool IsEnabled => _timer.IsEnabled;

    public event EventHandler? Tick;

    public void Start() => _timer.Start();

    public void StopTimer() => _timer.Stop();

    public void Dispose()
    {
        _timer.Stop();
        Tick = null;
    }
}
