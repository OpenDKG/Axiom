// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Windows.Threading;
using Netrigil.Contracts.Monitoring;
using Netrigil.UI.ViewModels;

namespace Netrigil.UI.Services;

/// <summary>
/// Polls a connection source on the UI dispatcher and keeps one row per socket. The diff keeps
/// existing rows (and their sorting/selection) intact between polls.
/// </summary>
public sealed class ConnectionMonitor : IDisposable
{
    private readonly IConnectionSnapshotSource _source;
    private readonly DispatcherTimer _timer;
    private readonly Dictionary<string, ConnectionRow> _rows = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _cancellation = new();
    private bool _isPolling;

    public ConnectionMonitor(IConnectionSnapshotSource source)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _timer = new DispatcherTimer { Interval = source.PollInterval };
        _timer.Tick += OnTick;
    }

    public ObservableCollection<ConnectionRow> Connections { get; } = [];

    public string SourceName => _source.Name;

    public TimeSpan PollInterval => _source.PollInterval;

    public DateTimeOffset? LastCaptureUtc { get; private set; }

    public int ProcessCount { get; private set; }

    public IReadOnlyList<string> Limitations { get; private set; } = [];

    public string? LastError { get; private set; }

    public bool IsRunning => _timer.IsEnabled;

    public event EventHandler? Updated;

    public void Start()
    {
        if (_timer.IsEnabled)
        {
            return;
        }

        _timer.Start();
        _ = PollAsync();
    }

    public void Stop() => _timer.Stop();

    public async Task PollAsync()
    {
        if (_isPolling)
        {
            return;
        }

        _isPolling = true;

        try
        {
            var snapshot = await _source.CaptureAsync(_cancellation.Token).ConfigureAwait(true);
            Apply(snapshot);
            LastError = null;
        }
        catch (OperationCanceledException)
        {
            // Shutting down.
        }
#pragma warning disable CA1031 // A polling loop must not crash the shell on a transient OS error.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            LastError = exception.Message;
            Updated?.Invoke(this, EventArgs.Empty);
        }
        finally
        {
            _isPolling = false;
        }
    }

    public void Dispose()
    {
        _timer.Stop();
        _timer.Tick -= OnTick;
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
        Limitations = snapshot.Limitations;

        var seen = new HashSet<string>(StringComparer.Ordinal);

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

        foreach (var key in _rows.Keys.Where(key => !seen.Contains(key)).ToList())
        {
            if (_rows.Remove(key, out var removed))
            {
                Connections.Remove(removed);
            }
        }

        Updated?.Invoke(this, EventArgs.Empty);
    }

    private static string KeyOf(LiveConnection connection) =>
        $"{connection.Protocol}|{connection.LocalEndpoint}|{connection.RemoteEndpoint}|{connection.ProcessId}";
}
