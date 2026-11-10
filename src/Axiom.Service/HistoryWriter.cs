// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.Persistence;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>
/// Persists the stable part of the latest snapshot every two minutes and applies retention every
/// six hours. The database is local SQLite in WAL mode; no payload or DNS content is stored.
/// Short-lived sockets are skipped so a busy machine does not write a page per connection.
/// </summary>
public sealed partial class HistoryWriter(
    ConnectionSnapshotCache cache,
    HistoryStore store,
    ILogger<HistoryWriter> logger) : BackgroundService
{
    private readonly HashSet<string> _previousKeys = new(StringComparer.OrdinalIgnoreCase);

    private ConnectionSnapshot? _lastPersistable;
    private static readonly TimeSpan FlushInterval = TimeSpan.FromMinutes(2);

    private static readonly TimeSpan RetentionInterval = TimeSpan.FromHours(6);

    [LoggerMessage(EventId = 3001, Level = LogLevel.Information, Message = "History database: {Path}")]
    private static partial void LogDatabase(ILogger logger, string path);

    [LoggerMessage(EventId = 3002, Level = LogLevel.Warning, Message = "History write failed")]
    private static partial void LogWriteFailure(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 3003, Level = LogLevel.Information, Message = "Retention removed {Rows} flow rows")]
    private static partial void LogRetention(ILogger logger, int rows);

    private static string ConnectionKey(LiveConnection connection) =>
        string.Join(
            '\u001f',
            connection.AppPath,
            connection.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            connection.Protocol.ToString(),
            connection.RemoteEndpoint);

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
                // Persist a connection only after it survived one refresh cycle. Short-lived
                // sockets (the bulk of the churn) never reach SQLite, which keeps page writes low.
                var stable = new List<LiveConnection>();
                var currentKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var connection in snapshot.Connections)
                {
                    var key = ConnectionKey(connection);
                    currentKeys.Add(key);
                    if (_previousKeys.Contains(key))
                    {
                        stable.Add(connection);
                    }
                }

                _previousKeys.Clear();
                foreach (var key in currentKeys)
                {
                    _previousKeys.Add(key);
                }

                var persistable = stable.Count == snapshot.Connections.Count
                    ? snapshot
                    : snapshot with { Connections = stable };
                _lastPersistable = persistable;

                try
                {
                    await store.UpsertAsync(persistable, cancellationToken: stoppingToken).ConfigureAwait(false);
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

        // One last write on shutdown keeps the final stable snapshot in history.
        if (_lastPersistable is { } last)
        {
            try
            {
                await store.UpsertAsync(last, cancellationToken: CancellationToken.None).ConfigureAwait(false);
            }
#pragma warning disable CA1031 // Best effort on shutdown; the host is already stopping.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                LogWriteFailure(logger, exception);
            }
        }
    }
}
