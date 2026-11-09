// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net.NetworkInformation;

namespace Axiom.Presentation;

public enum TrafficRange
{
    LastFiveMinutes = 0,
    LastHour = 1,
    LastTwelveHours = 2,
    LastDay = 3,
    LastWeek = 4,
    LastMonth = 5,
}

/// <summary>One timestamped system-wide throughput sample. NaN means the sample is unavailable.</summary>
public sealed record ThroughputSample(
    DateTimeOffset Timestamp,
    double Upload,
    double Download);

/// <summary>
/// Genuine local, system-wide interface throughput. The five-minute window is sampled live in the
/// desktop process; longer ranges come from the service's persisted per-minute history and stay
/// empty (gaps) where nothing was measured.
/// </summary>
public sealed class TrafficEngine : IDisposable
{
    public const int BucketCount = 300;

    private readonly IUiTimer _timer;
    private Dictionary<string, (long Sent, long Received)> _previous = new(StringComparer.Ordinal);
    private long _lastTimestamp;
    private TrafficRange _range = TrafficRange.LastFiveMinutes;
    private bool _historyLoaded;
    private int _historyBucketSeconds = 60;
    private string? _historyDetail;

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
    public double LatestUpload => Samples.Count > 0 ? Samples[^1].Upload : double.NaN;
    public double LatestDownload => Samples.Count > 0 ? Samples[^1].Download : double.NaN;

    /// <summary>True when a historical range has at least one bucket with a measurement.</summary>
    public bool HasHistoryData =>
        !IsLive && _historyLoaded &&
        (UploadSeries.Any(double.IsFinite) || DownloadSeries.Any(double.IsFinite));

    /// <summary>Width of one stored history bucket for a range, in seconds.</summary>
    public static int BucketSecondsFor(TrafficRange range) => range switch
    {
        TrafficRange.LastHour => 60,
        TrafficRange.LastTwelveHours => 300,
        TrafficRange.LastDay => 300,
        TrafficRange.LastWeek => 3_600,
        TrafficRange.LastMonth => 21_600,
        _ => 1,
    };

    public string BucketLabel => _range switch
    {
        TrafficRange.LastFiveMinutes => "1 s samples · rolling 5m · system-wide",
        _ => $"{FormatBucket(_historyBucketSeconds)} buckets · {RangeText(_range)} · system-wide",
    };

    public string RangeNote => IsLive
        ? "Measured on active network interfaces. Per-app rates require separate telemetry."
        : _historyDetail ??
          "Reading system-wide throughput history from the local Axiom service…";

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
                if (IsLive)
                {
                    UploadSeries.Add(double.NaN);
                    DownloadSeries.Add(double.NaN);
                }

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
        RefreshSeries();
        Updated?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Replaces the series with persisted history. A bucket without measured seconds becomes a NaN
    /// point, so the chart draws a gap instead of an invented zero.
    /// </summary>
    public void SetHistory(
        TrafficRange range,
        int bucketSeconds,
        IReadOnlyList<double> upload,
        IReadOnlyList<double> download,
        string? detail)
    {
        if (range != _range)
        {
            return;
        }

        _historyLoaded = true;
        _historyBucketSeconds = Math.Max(1, bucketSeconds);
        _historyDetail = detail;

        UploadSeries.Clear();
        DownloadSeries.Clear();
        foreach (var value in upload)
        {
            UploadSeries.Add(value);
        }

        foreach (var value in download)
        {
            DownloadSeries.Add(value);
        }

        Updated?.Invoke(this, EventArgs.Empty);
    }

    public void SetHistoryUnavailable(string reason)
    {
        _historyLoaded = false;
        _historyDetail = reason;
        UploadSeries.Clear();
        DownloadSeries.Clear();
        Updated?.Invoke(this, EventArgs.Empty);
    }

    private void RefreshSeries()
    {
        UploadSeries.Clear();
        DownloadSeries.Clear();
        _historyLoaded = false;
        _historyDetail = null;
        if (!IsLive)
        {
            return;
        }

        foreach (var sample in Samples)
        {
            UploadSeries.Add(sample.Upload);
            DownloadSeries.Add(sample.Download);
        }
    }

    private static string RangeText(TrafficRange range) => range switch
    {
        TrafficRange.LastHour => "last 1h",
        TrafficRange.LastTwelveHours => "last 12h",
        TrafficRange.LastDay => "last 24h",
        TrafficRange.LastWeek => "last 7d",
        TrafficRange.LastMonth => "last 30d",
        _ => "last 5m",
    };

    private static string FormatBucket(int seconds) => seconds switch
    {
        < 60 => "1 s",
        < 3_600 => $"{seconds / 60} min",
        _ => $"{seconds / 3_600} h",
    };

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
            if (IsLive && UploadSeries.Count > 0 && DownloadSeries.Count > 0)
            {
                UploadSeries.RemoveAt(0);
                DownloadSeries.RemoveAt(0);
            }

            Samples.RemoveAt(0);
        }

        Samples.Add(new ThroughputSample(timestamp, upload, download));
        if (IsLive)
        {
            UploadSeries.Add(upload);
            DownloadSeries.Add(download);
        }
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
