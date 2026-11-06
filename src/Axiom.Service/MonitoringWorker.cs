// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Platform;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>Polls the platform socket inventory once per interval and publishes the latest snapshot.</summary>
public sealed partial class MonitoringWorker(
    ConnectionSnapshotCache cache,
    IServicePlatform platform,
    ILogger<MonitoringWorker> logger) : BackgroundService
{
    [LoggerMessage(EventId = 1001, Level = LogLevel.Information, Message = "Monitoring source: {Source}, interval {Interval}")]
    private static partial void LogSource(ILogger logger, string source, TimeSpan interval);

    [LoggerMessage(EventId = 1002, Level = LogLevel.Warning, Message = "Snapshot capture failed")]
    private static partial void LogCaptureFailure(ILogger logger, Exception exception);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var source = platform.CreateSnapshotSource();
        cache.SourceName = source.Name;
        cache.PollInterval = source.PollInterval;

        LogSource(logger, source.Name, source.PollInterval);

#if !WINDOWS
        var hostLimitations = Axiom.Infrastructure.Linux.LinuxHostEnvironment.Detect().Describe();
#endif

        using var timer = new PeriodicTimer(source.PollInterval);

        do
        {
            try
            {
                var snapshot = await source.CaptureAsync(stoppingToken).ConfigureAwait(false);
#if !WINDOWS
                if (hostLimitations.Count > 0)
                {
                    snapshot = snapshot with
                    {
                        Limitations = [.. snapshot.Limitations, .. hostLimitations],
                    };
                }
#endif
                cache.Update(snapshot);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
#pragma warning disable CA1031 // A transient OS error must not stop the service loop.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                cache.Fail(exception.Message);
                LogCaptureFailure(logger, exception);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }
}
