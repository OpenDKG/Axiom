// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Net.NetworkInformation;
using Axiom.Persistence;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>
/// Records system-wide interface throughput as one row per minute so the Overview page can show
/// 1h to 30d history instead of only the live five minutes. It reads the same interface counters
/// the desktop plots live and stores byte totals only - no payload, host or DNS content.
/// </summary>
public sealed partial class ThroughputRecorderWorker(
    HistoryStore store,
    ILogger<ThroughputRecorderWorker> logger) : BackgroundService
{
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan FlushInterval = TimeSpan.FromMinutes(5);
    private const int MaxPendingMinutes = 24 * 60;

    private readonly List<ThroughputBucket> _pendingBuckets = [];

    private readonly Dictionary<string, (long Sent, long Received)> _previous =
        new(StringComparer.Ordinal);

    private long _lastTimestamp;
    private DateTimeOffset _bucketStart;
    private long _uploadBytes;
    private long _downloadBytes;
    private double _measuredSeconds;
    private DateTimeOffset _lastFlush;

    [LoggerMessage(EventId = 5001, Level = LogLevel.Debug, Message = "Throughput recorder started")]
    private static partial void LogStarted(ILogger logger);

    [LoggerMessage(EventId = 5002, Level = LogLevel.Warning, Message = "Throughput bucket write failed")]
    private static partial void LogWriteFailure(ILogger logger, Exception exception);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _bucketStart = FloorToMinute(DateTimeOffset.UtcNow);
        _previous.Clear();
        foreach (var (id, counters) in ReadCounters())
        {
            _previous[id] = counters;
        }

        _lastTimestamp = Stopwatch.GetTimestamp();
        _lastFlush = DateTimeOffset.UtcNow;
        LogStarted(logger);

        using var timer = new PeriodicTimer(SampleInterval);

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                var now = DateTimeOffset.UtcNow;
                Accumulate(ReadCounters());

                if (now >= _bucketStart.AddMinutes(1))
                {
                    // Keep completed minutes in memory and write them in one batch later.
                    if (_measuredSeconds > 0)
                    {
                        if (_pendingBuckets.Count >= MaxPendingMinutes)
                        {
                            _pendingBuckets.RemoveAt(0);
                        }

                        _pendingBuckets.Add(new ThroughputBucket(
                            _bucketStart,
                            _uploadBytes,
                            _downloadBytes,
                            _measuredSeconds));
                    }

                    _bucketStart = FloorToMinute(now);
                    _uploadBytes = 0;
                    _downloadBytes = 0;
                    _measuredSeconds = 0;

                    if (_pendingBuckets.Count >= 12)
                    {
                        await FlushAsync(stoppingToken).ConfigureAwait(false);
                    }

                    continue;
                }

                if (now - _lastFlush >= FlushInterval)
                {
                    await FlushAsync(stoppingToken).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }

        // Best effort on shutdown; the host is already stopping.
        await FlushAsync(CancellationToken.None).ConfigureAwait(false);
    }

    private void Accumulate(Dictionary<string, (long Sent, long Received)> current)
    {
        var timestamp = Stopwatch.GetTimestamp();
        var elapsed = (timestamp - _lastTimestamp) / (double)Stopwatch.Frequency;
        _lastTimestamp = timestamp;

        if (elapsed <= 0 || elapsed >= 1.5)
        {
            // A long pause is a gap, not a burst. Skip it and resynchronise the counters.
            ReplacePrevious(current);
            return;
        }

        long sent = 0;
        long received = 0;
        var matched = 0;
        foreach (var (id, counters) in current)
        {
            if (!_previous.TryGetValue(id, out var prior) ||
                counters.Sent < prior.Sent ||
                counters.Received < prior.Received)
            {
                continue;
            }

            sent += counters.Sent - prior.Sent;
            received += counters.Received - prior.Received;
            matched++;
        }

        var stable = matched > 0 && matched == current.Count && current.Count == _previous.Count;
        ReplacePrevious(current);
        if (!stable)
        {
            return;
        }

        _uploadBytes += sent;
        _downloadBytes += received;
        _measuredSeconds += elapsed;
    }

    private async Task FlushAsync(CancellationToken cancellationToken)
    {
        _lastFlush = DateTimeOffset.UtcNow;

        var buckets = new List<ThroughputBucket>(_pendingBuckets);
        if (_measuredSeconds > 0)
        {
            buckets.Add(new ThroughputBucket(_bucketStart, _uploadBytes, _downloadBytes, _measuredSeconds));
        }

        if (buckets.Count == 0)
        {
            return;
        }

        try
        {
            await store.RecordThroughputBatchAsync(buckets, cancellationToken).ConfigureAwait(false);
            _pendingBuckets.Clear();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            LogWriteFailure(logger, exception);
        }
    }

    private void ReplacePrevious(Dictionary<string, (long Sent, long Received)> current)
    {
        _previous.Clear();
        foreach (var (id, counters) in current)
        {
            _previous[id] = counters;
        }
    }

    private static DateTimeOffset FloorToMinute(DateTimeOffset value) =>
        new(value.Year, value.Month, value.Day, value.Hour, value.Minute, 0, TimeSpan.Zero);

    private static Dictionary<string, (long Sent, long Received)> ReadCounters()
    {
        var counters = new Dictionary<string, (long, long)>(StringComparer.Ordinal);
        try
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (adapter.OperationalStatus != OperationalStatus.Up ||
                    adapter.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                {
                    continue;
                }

                try
                {
                    var stats = adapter.GetIPStatistics();
                    counters[adapter.Id] = (stats.BytesSent, stats.BytesReceived);
                }
                catch (NetworkInformationException)
                {
                    // An adapter can disappear mid-read; leave it as a gap.
                }
            }
        }
        catch (NetworkInformationException)
        {
            return counters;
        }

        return counters;
    }
}
