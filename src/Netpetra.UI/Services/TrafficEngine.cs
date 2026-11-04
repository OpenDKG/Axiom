// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Windows.Threading;

namespace Netpetra.UI.Services;

public enum TrafficRange
{
    LastMinute = 0,
    LastHour = 1,
    LastDay = 2,
    LastWeek = 3,
}

/// <summary>
/// Builds the overview throughput series. The 5-minute view samples real system-wide IPv4/IPv6
/// interface byte counters once per second. Longer ranges keep the deterministic demo shape until
/// byte history is stored; per-process byte accounting still needs ETW (FND-004).
/// </summary>
public sealed class TrafficEngine : IDisposable
{
    public const int BucketCount = 60;

    private const int Seed = 20261101;

    private readonly DispatcherTimer _timer;

    private TrafficRange _range = TrafficRange.LastMinute;

    private (long Sent, long Received)? _lastSample;

    private long _lastTimestamp;

    public TrafficEngine()
    {
        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1),
        };
        _timer.Tick += OnTimerTick;
    }

    public ObservableCollection<double> UploadSeries { get; } = [];

    public ObservableCollection<double> DownloadSeries { get; } = [];

    /// <summary>Raised after a series update so the view model can refresh its labels.</summary>
    public event EventHandler? Updated;

    public TrafficRange Range => _range;

    public bool IsLive => _range == TrafficRange.LastMinute;

    public double LatestUpload => UploadSeries.Count == 0 ? 0 : UploadSeries[^1];

    public double LatestDownload => DownloadSeries.Count == 0 ? 0 : DownloadSeries[^1];

    public string BucketLabel => _range switch
    {
        TrafficRange.LastMinute => "1 s buckets · last 60 s · system-wide",
        TrafficRange.LastHour => "60 s buckets · last hour · demo",
        TrafficRange.LastDay => "24 min buckets · last day · demo",
        TrafficRange.LastWeek => "2.8 h buckets · last week · demo",
        _ => "demo buckets",
    };

    public string RangeNote => IsLive
        ? "Real system-wide interface counters; per-process bytes need ETW (FND-004)."
        : "Fixed demo shape; switch to 5m for real system-wide counters.";

    public void Start()
    {
        ResetSeries();
        _timer.Start();
    }

    public void Stop() => _timer.Stop();

    public void SetRange(TrafficRange range)
    {
        if (_range == range)
        {
            return;
        }

        _range = range;
        ResetSeries();
        Updated?.Invoke(this, EventArgs.Empty);
    }

    public void Dispose()
    {
        _timer.Stop();
        _timer.Tick -= OnTimerTick;
    }

    private void OnTimerTick(object? sender, EventArgs e)
    {
        if (!IsLive)
        {
            return;
        }

        var sample = ReadCounters();
        if (_lastSample is not { } previous)
        {
            _lastSample = sample;
            _lastTimestamp = Stopwatch.GetTimestamp();
            return;
        }

        var elapsed = (Stopwatch.GetTimestamp() - _lastTimestamp) / (double)Stopwatch.Frequency;
        if (elapsed <= 0)
        {
            elapsed = 1;
        }

        var sent = Math.Max(0, sample.Sent - previous.Sent);
        var received = Math.Max(0, sample.Received - previous.Received);
        _lastSample = sample;
        _lastTimestamp = Stopwatch.GetTimestamp();

        Push(sent / elapsed, received / elapsed);
    }

    private void ResetSeries()
    {
        UploadSeries.Clear();
        DownloadSeries.Clear();

        if (IsLive)
        {
            for (var i = 0; i < BucketCount; i++)
            {
                UploadSeries.Add(0);
                DownloadSeries.Add(0);
            }

            _lastSample = ReadCounters();
            _lastTimestamp = Stopwatch.GetTimestamp();
            return;
        }

        RegenerateDemo();
    }

    private void Push(double upload, double download)
    {
        UploadSeries.RemoveAt(0);
        UploadSeries.Add(upload);
        DownloadSeries.RemoveAt(0);
        DownloadSeries.Add(download);
        Updated?.Invoke(this, EventArgs.Empty);
    }

    private void RegenerateDemo()
    {
        UploadSeries.Clear();
        DownloadSeries.Clear();

        var random = new Random(Seed + ((int)_range * 7919));
        var upload = InitialUpload(random);
        var download = InitialDownload(random);

        for (var i = 0; i < BucketCount; i++)
        {
            upload = NextUploadSample(random, upload, i);
            download = NextDownloadSample(random, download, i);
            UploadSeries.Add(upload);
            DownloadSeries.Add(download);
        }
    }

    private static (long Sent, long Received) ReadCounters()
    {
        long sent = 0;
        long received = 0;

        try
        {
            foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (networkInterface.OperationalStatus != OperationalStatus.Up ||
                    networkInterface.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                {
                    continue;
                }

                try
                {
                    var statistics = networkInterface.GetIPStatistics();
                    sent += statistics.BytesSent;
                    received += statistics.BytesReceived;
                }
                catch (NetworkInformationException)
                {
                }
                catch (InvalidOperationException)
                {
                }
            }
        }
        catch (NetworkInformationException)
        {
            return (0, 0);
        }
        catch (PlatformNotSupportedException)
        {
            return (0, 0);
        }

        return (sent, received);
    }

    private static double InitialUpload(Random random) => 90_000 + (random.NextDouble() * 60_000);

    private static double InitialDownload(Random random) => 900_000 + (random.NextDouble() * 700_000);

    private static double NextUploadSample(Random random, double previous, int index)
    {
        var wave = Math.Sin((index / (double)BucketCount) * Math.PI * 2) * 60_000;
        var noise = (random.NextDouble() - 0.5) * 26_000;
        return Math.Max(20_000, previous * 0.82 + wave * 0.45 + noise);
    }

    private static double NextDownloadSample(Random random, double previous, int index)
    {
        var wave = Math.Sin((index / (double)BucketCount) * Math.PI * 4) * 300_000;
        var noise = (random.NextDouble() - 0.5) * 220_000;
        var spike = index % 17 == 0 ? 900_000 : 0;
        return Math.Max(120_000, previous * 0.8 + wave + noise + spike);
    }
}
