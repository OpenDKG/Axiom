// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;

namespace LocalFirewall.UI.Services;

public enum DemoTimerRange
{
    LastMinute = 0,
    LastHour = 1,
    LastDay = 2,
    LastWeek = 3,
}

/// <summary>
/// Produces the two demo throughput series drawn by the overview chart. Everything here is
/// synthetic: the values are not read from the operating system and are labelled DEMO DATA.
/// </summary>
public sealed class DemoTrafficEngine : IDisposable
{
    public const int BucketCount = 60;

    private const int Seed = 20261101;

    private readonly System.Windows.Threading.DispatcherTimer _timer;
    private DemoTimerRange _range = DemoTimerRange.LastMinute;

    public DemoTrafficEngine()
    {
        _timer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1),
        };
        _timer.Tick += OnTimerTick;
    }

    public ObservableCollection<double> UploadSeries { get; } = [];

    public ObservableCollection<double> DownloadSeries { get; } = [];

    /// <summary>Raised after a series update so the view model can refresh its labels.</summary>
    public event EventHandler? Updated;

    public DemoTimerRange Range => _range;

    public double LatestUpload => UploadSeries.Count == 0 ? 0 : UploadSeries[^1];

    public double LatestDownload => DownloadSeries.Count == 0 ? 0 : DownloadSeries[^1];

    public string BucketLabel => _range switch
    {
        DemoTimerRange.LastMinute => "1 s buckets · last 60 s",
        DemoTimerRange.LastHour => "60 s buckets · last hour",
        DemoTimerRange.LastDay => "24 min buckets · last day",
        DemoTimerRange.LastWeek => "2.8 h buckets · last week",
        _ => "demo buckets",
    };

    public void Start()
    {
        Regenerate();
        _timer.Start();
    }

    public void Stop() => _timer.Stop();

    public void SetRange(DemoTimerRange range)
    {
        if (_range == range)
        {
            return;
        }

        _range = range;
        Regenerate();
        Updated?.Invoke(this, EventArgs.Empty);
    }

    public void Dispose()
    {
        _timer.Stop();
        _timer.Tick -= OnTimerTick;
    }

    private void OnTimerTick(object? sender, EventArgs e)
    {
        // Only the live minute view scrolls. Historical ranges show a fixed demo shape until the
        // real SQLite-backed history exists (FND-005).
        if (_range != DemoTimerRange.LastMinute || UploadSeries.Count == 0)
        {
            return;
        }

        UploadSeries.RemoveAt(0);
        UploadSeries.Add(NextUpload(UploadSeries[^1]));
        DownloadSeries.RemoveAt(0);
        DownloadSeries.Add(NextDownload(DownloadSeries[^1]));

        Updated?.Invoke(this, EventArgs.Empty);
    }

    private void Regenerate()
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

    private static double InitialUpload(Random random) => 90_000 + (random.NextDouble() * 60_000);

    private static double InitialDownload(Random random) => 900_000 + (random.NextDouble() * 700_000);

    private static double NextUpload(double previous)
    {
        var drift = (Random.Shared.NextDouble() - 0.5) * 18_000;
        var pull = (140_000 - previous) * 0.08;
        return Math.Clamp(previous + drift + pull, 40_000, 420_000);
    }

    private static double NextDownload(double previous)
    {
        var drift = (Random.Shared.NextDouble() - 0.5) * 120_000;
        var pull = (1_700_000 - previous) * 0.06;
        return Math.Clamp(previous + drift + pull, 250_000, 4_200_000);
    }

    private double NextUploadSample(Random random, double previous, int index)
    {
        var wave = Math.Sin((index / (double)BucketCount) * Math.PI * 2) * RangeWaveAmplitude();
        var noise = (random.NextDouble() - 0.5) * 26_000;
        return Math.Max(20_000, previous * 0.82 + wave * 0.45 + noise);
    }

    private double NextDownloadSample(Random random, double previous, int index)
    {
        var wave = Math.Sin((index / (double)BucketCount) * Math.PI * 4) * RangeWaveAmplitude() * 5;
        var noise = (random.NextDouble() - 0.5) * 220_000;
        var spike = index % 17 == 0 ? 900_000 : 0;
        return Math.Max(120_000, previous * 0.8 + wave + noise + spike);
    }

    private double RangeWaveAmplitude() => _range switch
    {
        DemoTimerRange.LastMinute => 60_000,
        DemoTimerRange.LastHour => 90_000,
        DemoTimerRange.LastDay => 140_000,
        DemoTimerRange.LastWeek => 120_000,
        _ => 60_000,
    };
}
