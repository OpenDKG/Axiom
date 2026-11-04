// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Windows.Threading;

namespace Netpetra.UI.Services;

public enum TrafficRange
{
    LastFiveMinutes = 0,
    LastHour = 1,
    LastDay = 2,
    LastWeek = 3,
    LastMonth = 4,
}

/// <summary>
/// Genuine local, system-wide interface throughput for a rolling five-minute window.
/// Persistent history is not yet available; never synthesize older traffic.
/// Rates are derived only from consecutive samples of the same operational interface.
/// </summary>
public sealed class TrafficEngine : IDisposable
{
    public const int BucketCount = 300;

    private readonly DispatcherTimer _timer;
    private Dictionary<string, (long Sent, long Received)> _previous = new(StringComparer.Ordinal);
    private long _lastTimestamp;
    private TrafficRange _range = TrafficRange.LastFiveMinutes;

    public TrafficEngine()
    {
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += OnTimerTick;
    }

    public ObservableCollection<double> UploadSeries { get; } = [];
    public ObservableCollection<double> DownloadSeries { get; } = [];

    public event EventHandler? Updated;

    public TrafficRange Range => _range;
    public bool IsLive => _range == TrafficRange.LastFiveMinutes;
    public double LatestUpload => IsLive && UploadSeries.Count > 0 ? UploadSeries[^1] : double.NaN;
    public double LatestDownload => IsLive && DownloadSeries.Count > 0 ? DownloadSeries[^1] : double.NaN;

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

        if (UploadSeries.Count == 0)
        {
            for (var i = 0; i < BucketCount; i++)
            {
                UploadSeries.Add(double.NaN);
                DownloadSeries.Add(double.NaN);
            }
        }

        _previous = ReadCounters();
        _lastTimestamp = Stopwatch.GetTimestamp();
        _timer.Start();
        Updated?.Invoke(this, EventArgs.Empty);
    }

    public void Stop() => _timer.Stop();

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
        _timer.Stop();
        _timer.Tick -= OnTimerTick;
    }

    private void OnTimerTick(object? sender, EventArgs e)
    {
        // Continue collecting the real 5m window even if the user selects an unavailable
        // historical range, so switching back does not erase measured data.
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

            // A changed adapter set means a partial sum, not a trustworthy total.
            if (matched > 0 && matched == current.Count && current.Count == _previous.Count)
            {
                upload = sent / elapsed;
                download = received / elapsed;
            }
        }

        // Missing interfaces, counter resets or delayed UI ticks are gaps, not zero.
        _previous = current;
        _lastTimestamp = now;

        // A delayed dispatcher tick (sleep/hibernation/UI stall) must not stretch
        // stale samples across the five-minute time axis.
        if (elapsed >= 1.5)
        {
            var missingSeconds = (int)Math.Clamp(Math.Round(elapsed) - 1, 0, BucketCount);
            for (var i = 0; i < missingSeconds; i++)
            {
                Push(double.NaN, double.NaN);
            }
        }

        Push(upload, download);
        Updated?.Invoke(this, EventArgs.Empty);
    }

    private void Push(double upload, double download)
    {
        if (UploadSeries.Count == BucketCount)
        {
            UploadSeries.RemoveAt(0);
            DownloadSeries.RemoveAt(0);
        }

        UploadSeries.Add(upload);
        DownloadSeries.Add(download);
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
                    // No data from this adapter: do not invent a zero-byte sample.
                }
                catch (InvalidOperationException)
                {
                }
            }
        }
        catch (NetworkInformationException)
        {
        }
        catch (PlatformNotSupportedException)
        {
        }

        return counters;
    }
}
