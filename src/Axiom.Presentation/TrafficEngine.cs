// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net.NetworkInformation;

namespace Axiom.Presentation;

public enum TrafficRange
{
    LastFiveMinutes = 0,
    LastHour = 1,
    LastDay = 2,
    LastWeek = 3,
    LastMonth = 4,
}

/// <summary>One timestamped system-wide throughput sample. NaN means the sample is unavailable.</summary>
public sealed record ThroughputSample(
    DateTimeOffset Timestamp,
    double Upload,
    double Download);

/// <summary>
/// Genuine local, system-wide interface throughput for a rolling five-minute window. Persistent
/// history is not yet available; older ranges stay unavailable instead of being synthesized.
/// </summary>
public sealed class TrafficEngine : IDisposable
{
    public const int BucketCount = 300;

    private readonly IUiTimer _timer;
    private Dictionary<string, (long Sent, long Received)> _previous = new(StringComparer.Ordinal);
    private long _lastTimestamp;
    private TrafficRange _range = TrafficRange.LastFiveMinutes;

    public TrafficEngine(IUiTimerFactory timers)
    {
        ArgumentNullException.ThrowIfNull(timers);
        _timer = timers.Create(TimeSpan.FromSeconds(1));
        _timer.Tick += OnTimerTick;
    }

    public ObservableCollection<double> UploadSeries { get; } = [];
    public ObservableCollection<double> DownloadSeries { get; } = [];

    public ObservableCollection<ThroughputSample> Samples { get; } = [];

    public event EventHandler? Updated;

    public TrafficRange Range => _range;
    public bool IsLive => _range == TrafficRange.LastFiveMinutes;
    public double LatestUpload => IsLive && Samples.Count > 0 ? Samples[^1].Upload : double.NaN;
    public double LatestDownload => IsLive && Samples.Count > 0 ? Samples[^1].Download : double.NaN;

    public string BucketLabel => _range switch
    {
        TrafficRange.LastFiveMinutes => "1 s samples · rolling 5m · system-wide",
        TrafficRange.LastHour => "1h · historical byte samples not recorded",
        TrafficRange.LastDay => "24h · historical byte samples not recorded",
        TrafficRange.LastWeek => "7d · historical byte samples not recorded",
        TrafficRange.LastMonth => "30d · historical byte samples not recorded",
        _ => "No historical data",
    };

    public string RangeNote => IsLive
        ? "Measured on active network interfaces. Per-app rates require separate telemetry."
        : "No historical byte data yet. Showing no data instead of simulated traffic.";

    public void Start()
    {
        if (_timer.IsEnabled)
        {
            return;
        }

        if (Samples.Count == 0)
        {
            var firstTimestamp = DateTimeOffset.UtcNow.AddSeconds(-(BucketCount - 1));
            for (var i = 0; i < BucketCount; i++)
            {
                UploadSeries.Add(double.NaN);
                DownloadSeries.Add(double.NaN);
                Samples.Add(new ThroughputSample(firstTimestamp.AddSeconds(i), double.NaN, double.NaN));
            }
        }

        _previous = ReadCounters();
        _lastTimestamp = Stopwatch.GetTimestamp();
        _timer.Start();
        Updated?.Invoke(this, EventArgs.Empty);
    }

    public void Stop() => _timer.StopTimer();

    public void SetRange(TrafficRange range)
    {
        if (_range == range)
        {
            return;
        }

        _range = range;
        Updated?.Invoke(this, EventArgs.Empty);
    }

    public void Dispose()
    {
        _timer.StopTimer();
        _timer.Tick -= OnTimerTick;
        _timer.Dispose();
    }

    private void OnTimerTick(object? sender, EventArgs e)
    {
        var current = ReadCounters();
        var now = Stopwatch.GetTimestamp();
        var elapsed = (now - _lastTimestamp) / (double)Stopwatch.Frequency;
        double upload = double.NaN;
        double download = double.NaN;
        long sent = 0;
        long received = 0;
        var matched = 0;

        if (elapsed > 0 && elapsed < 1.5)
        {
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

            if (matched > 0 && matched == current.Count && current.Count == _previous.Count)
            {
                upload = sent / elapsed;
                download = received / elapsed;
            }
        }

        _previous = current;
        _lastTimestamp = now;

        var nowTimestamp = DateTimeOffset.UtcNow;
        if (elapsed >= 1.5)
        {
            var missingSeconds = (int)Math.Clamp(Math.Round(elapsed) - 1, 0, BucketCount);
            var missingStart = nowTimestamp.AddSeconds(-missingSeconds);
            for (var i = 0; i < missingSeconds; i++)
            {
                Push(double.NaN, double.NaN, missingStart.AddSeconds(i));
            }
        }

        Push(upload, download, nowTimestamp);
        Updated?.Invoke(this, EventArgs.Empty);
    }

    private void Push(double upload, double download, DateTimeOffset timestamp)
    {
        if (Samples.Count == BucketCount)
        {
            UploadSeries.RemoveAt(0);
            DownloadSeries.RemoveAt(0);
            Samples.RemoveAt(0);
        }

        UploadSeries.Add(upload);
        DownloadSeries.Add(download);
        Samples.Add(new ThroughputSample(timestamp, upload, download));
    }

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
