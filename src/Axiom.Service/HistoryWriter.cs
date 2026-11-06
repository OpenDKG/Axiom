// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Persistence;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>
/// Persists the latest snapshot every two seconds (not per poll) and applies retention hourly.
/// The database is local SQLite in WAL mode; no payload or DNS content is stored.
/// </summary>
public sealed partial class HistoryWriter(
    ConnectionSnapshotCache cache,
    HistoryStore store,
    ILogger<HistoryWriter> logger) : BackgroundService
{
    private static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(2);

    private static readonly TimeSpan RetentionInterval = TimeSpan.FromHours(1);

    [LoggerMessage(EventId = 3001, Level = LogLevel.Information, Message = "History database: {Path}")]
    private static partial void LogDatabase(ILogger logger, string path);

    [LoggerMessage(EventId = 3002, Level = LogLevel.Warning, Message = "History write failed")]
    private static partial void LogWriteFailure(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 3003, Level = LogLevel.Information, Message = "Retention removed {Rows} flow rows")]
    private static partial void LogRetention(ILogger logger, int rows);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await store.InitializeAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            LogWriteFailure(logger, exception);
            return;
        }

        LogDatabase(logger, store.DatabasePath);

        var lastRetention = DateTimeOffset.MinValue;

        using var timer = new PeriodicTimer(FlushInterval);
        long lastRevision = -1;

        do
        {
            // Capture the revision before the snapshot. If a newer snapshot arrives while the
            // write is in progress, the next tick must still see a revision greater than the one
            // recorded here; reading Revision after the write could silently skip that snapshot.
            var revision = cache.Revision;
            var snapshot = cache.Latest;
            if (snapshot is not null && revision != lastRevision)
            {
                try
                {
                    await store.UpsertAsync(snapshot, stoppingToken).ConfigureAwait(false);
                    lastRevision = revision;
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
#pragma warning disable CA1031 // A transient SQLite error must not stop the service.
                catch (Exception exception)
#pragma warning restore CA1031
                {
                    LogWriteFailure(logger, exception);
                }
            }

            if (DateTimeOffset.UtcNow - lastRetention >= RetentionInterval)
            {
                try
                {
                    var removed = await store
                        .ApplyRetentionAsync(DateTimeOffset.UtcNow, HistoryStore.DefaultRetention, stoppingToken)
                        .ConfigureAwait(false);

                    lastRetention = DateTimeOffset.UtcNow;
                    LogRetention(logger, removed);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
#pragma warning disable CA1031
                catch (Exception exception)
#pragma warning restore CA1031
                {
                    LogWriteFailure(logger, exception);
                }
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }
}
