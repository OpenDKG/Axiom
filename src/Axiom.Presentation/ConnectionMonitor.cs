// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using Axiom.Contracts.Monitoring;

namespace Axiom.Presentation;

/// <summary>
/// Polls a connection source on the host UI timer and keeps one row per socket. The diff keeps
/// existing rows (and their sorting/selection) intact between polls. No WPF/Avalonia dependency.
/// </summary>
public sealed class ConnectionMonitor : IDisposable
{
    private readonly IConnectionSnapshotSource _source;
    private readonly IUiTimer _timer;
    private readonly Dictionary<SocketKey, ConnectionRow> _rows = [];
    private readonly CancellationTokenSource _cancellation = new();
    private bool _isPolling;
    private bool _disposed;

    public ConnectionMonitor(IConnectionSnapshotSource source, IUiTimerFactory timers)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        ArgumentNullException.ThrowIfNull(timers);
        _timer = timers.Create(source.PollInterval);
        _timer.Tick += OnTick;
    }

    public ObservableCollection<ConnectionRow> Connections { get; } = [];

    public string SourceName => _source.Name;

    public TimeSpan PollInterval => _source.PollInterval;

    public DateTimeOffset? LastCaptureUtc { get; private set; }

    public IReadOnlyList<AppTrafficTotals> AppTraffic { get; private set; } = [];

    public int ProcessCount { get; private set; }

    public IReadOnlyList<string> Limitations { get; private set; } = [];

    public string? LastError { get; private set; }

    public bool IsRunning => _timer.IsEnabled;

    public event EventHandler? Updated;

    public void Start()
    {
        if (_disposed || _timer.IsEnabled)
        {
            return;
        }

        _timer.Start();
        _ = PollAsync();
    }

    public void Stop()
    {
        if (!_disposed)
        {
            _timer.StopTimer();
        }
    }

    public async Task PollAsync()
    {
        if (_disposed || _isPolling)
        {
            return;
        }

        var cancellationToken = _cancellation.Token;
        _isPolling = true;
        try
        {
            try
            {
                var snapshot = await _source.CaptureAsync(cancellationToken).ConfigureAwait(true);
                if (_disposed)
                {
                    return;
                }

                LastError = null;
                Apply(snapshot);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
#pragma warning disable CA1031 // A polling loop must not crash the shell on a transient OS error.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                if (_disposed)
                {
                    return;
                }

                LastError = exception.Message;
            }

            if (!_disposed)
            {
                Updated?.Invoke(this, EventArgs.Empty);
            }
        }
        finally
        {
            _isPolling = false;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _timer.StopTimer();
        _timer.Tick -= OnTick;
        _timer.Dispose();
        _cancellation.Cancel();
        _cancellation.Dispose();
    }

    private async void OnTick(object? sender, EventArgs e)
    {
        await PollAsync().ConfigureAwait(true);
    }

    private void Apply(ConnectionSnapshot snapshot)
    {
        LastCaptureUtc = snapshot.CapturedUtc;
        ProcessCount = snapshot.ProcessCount;
        AppTraffic = snapshot.AppTraffic;
        Limitations = snapshot.Limitations;

        var seen = new HashSet<SocketKey>(snapshot.Connections.Count);

        foreach (var connection in snapshot.Connections)
        {
            var key = KeyOf(connection);
            if (!seen.Add(key))
            {
                continue;
            }

            if (_rows.TryGetValue(key, out var existing))
            {
                existing.Update(connection);
            }
            else
            {
                var row = new ConnectionRow(connection);
                _rows.Add(key, row);
                Connections.Add(row);
            }
        }

        for (var index = Connections.Count - 1; index >= 0; index--)
        {
            var key = KeyOf(Connections[index].Source);
            if (!seen.Contains(key))
            {
                _rows.Remove(key);
                Connections.RemoveAt(index);
            }
        }
    }

    private static SocketKey KeyOf(LiveConnection connection) =>
        new(connection.Protocol, connection.LocalEndpoint, connection.RemoteEndpoint, connection.ProcessId);

    private readonly record struct SocketKey(
        TransportProtocol Protocol,
        string LocalEndpoint,
        string RemoteEndpoint,
        int ProcessId);
}
