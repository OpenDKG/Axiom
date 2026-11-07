namespace Axiom.Presentation;

/// <summary>Host-provided UI thread dispatch used by portable polling and command code.</summary>
public interface IUiDispatcher
{
    bool IsUiThread { get; }

    void Post(Action action);
}

/// <summary>A single host-owned repeating timer. The host decides which thread it ticks on.</summary>
public interface IUiTimer : IDisposable
{
    TimeSpan Interval { get; set; }

    bool IsEnabled { get; }

    event EventHandler? Tick;

    void Start();

    void StopTimer();
}

/// <summary>Creates UI timers without referencing WPF or Avalonia in portable code.</summary>
public interface IUiTimerFactory
{
    IUiTimer Create(TimeSpan interval);
}
