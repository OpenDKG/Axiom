// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Netrigil.Contracts.History;
using Netrigil.Contracts.Monitoring;
using Microsoft.Data.Sqlite;

namespace Netrigil.Persistence;

/// <summary>
/// Local SQLite history of observed flows (FND-005). WAL, UTC timestamps, upsert by flow key,
/// retention and time-window queries. Byte buckets are created for FND-004 but stay unused.
/// </summary>
public sealed class HistoryStore
{
    public const int SchemaVersion = 1;

    public static readonly TimeSpan DefaultRetention = TimeSpan.FromDays(30);

    private const string SchemaSql = """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version     INTEGER NOT NULL PRIMARY KEY,
            applied_utc TEXT    NOT NULL,
            checksum    TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS apps (
            id              INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            app_key         TEXT    NOT NULL UNIQUE,
            display_name    TEXT    NOT NULL,
            executable_path TEXT    NOT NULL,
            first_seen_utc  TEXT    NOT NULL,
            last_seen_utc   TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS flows (
            id              INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            app_id          INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
            process_id      INTEGER NOT NULL,
            protocol        TEXT    NOT NULL,
            local_endpoint  TEXT    NOT NULL,
            remote_endpoint TEXT    NOT NULL,
            direction       TEXT    NOT NULL,
            state           TEXT    NOT NULL,
            quality         TEXT    NOT NULL,
            first_seen_utc  TEXT    NOT NULL,
            last_seen_utc   TEXT    NOT NULL,
            UNIQUE (app_id, protocol, local_endpoint, remote_endpoint, process_id)
        );

        CREATE INDEX IF NOT EXISTS ix_flows_last_seen ON flows(last_seen_utc);
        CREATE INDEX IF NOT EXISTS ix_flows_remote ON flows(remote_endpoint);
        CREATE INDEX IF NOT EXISTS ix_flows_app ON flows(app_id);

        CREATE TABLE IF NOT EXISTS traffic_buckets (
            app_id          INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
            remote_ip       TEXT,
            bucket_start_utc TEXT   NOT NULL,
            granularity     INTEGER NOT NULL,
            upload_bytes    INTEGER NOT NULL DEFAULT 0,
            download_bytes  INTEGER NOT NULL DEFAULT 0,
            event_count     INTEGER NOT NULL DEFAULT 0,
            measured        INTEGER NOT NULL DEFAULT 0,
            quality_flags   INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (app_id, bucket_start_utc, granularity, remote_ip)
        );

        CREATE TABLE IF NOT EXISTS settings (
            key            TEXT    NOT NULL PRIMARY KEY,
            value_json     TEXT    NOT NULL,
            schema_version INTEGER NOT NULL
        );
        """;

    private readonly string _connectionString;

    public HistoryStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        if (!Path.IsPathFullyQualified(databasePath))
        {
            throw new ArgumentException("Database path must be absolute.", nameof(databasePath));
        }

        DatabasePath = databasePath;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = true,
            ForeignKeys = true,
        }.ToString();
    }

    public string DatabasePath { get; }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(DatabasePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        try
        {
            await MigrateAsync(cancellationToken);
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 26)
        {
            RecoverCorruptDatabase();
            await MigrateAsync(cancellationToken);
        }
    }

    public async Task<int> UpsertAsync(ConnectionSnapshot snapshot, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var now = ToStorage(snapshot.CapturedUtc);
        var appIds = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var written = 0;

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        foreach (var flow in snapshot.Connections)
        {
            var key = AppKey(flow);
            if (!appIds.TryGetValue(key, out var appId))
            {
                appId = await UpsertAppAsync(connection, transaction, key, flow, now, cancellationToken);
                appIds[key] = appId;
            }

            await UpsertFlowAsync(connection, transaction, appId, flow, now, cancellationToken);
            written++;
        }

        await transaction.CommitAsync(cancellationToken);
        return written;
    }

    public async Task<HistoryPage> QueryAsync(HistoryQuery query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        var limit = Math.Clamp(query.Limit, 1, 5000);
        var offset = Math.Max(0, query.Offset);
        var from = ToStorage(query.FromUtc);
        var to = ToStorage(query.ToUtc);
        var search = string.IsNullOrWhiteSpace(query.Search)
            ? null
            : $"%{EscapeLike(query.Search.Trim())}%";

        const string where = """
            WHERE f.last_seen_utc >= $from
              AND f.last_seen_utc <= $to
              AND ($search IS NULL
                   OR a.display_name LIKE $search ESCAPE '\'
                   OR a.executable_path LIKE $search ESCAPE '\'
                   OR f.remote_endpoint LIKE $search ESCAPE '\'
                   OR CAST(f.process_id AS TEXT) LIKE $search ESCAPE '\')
            """;

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        int total;

        await using (var count = connection.CreateCommand())
        {
            count.CommandText = $"SELECT COUNT(*) FROM flows f JOIN apps a ON a.id = f.app_id {where};";
            AddRangeParameters(count, from, to, search);
            total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
        }

        var rows = new List<HistoryRow>();

        await using (var command = connection.CreateCommand())
        {
            command.CommandText = $"""
                SELECT a.display_name,
                       a.executable_path,
                       f.process_id,
                       f.protocol,
                       f.local_endpoint,
                       f.remote_endpoint,
                       f.direction,
                       f.state,
                       f.quality,
                       f.first_seen_utc,
                       f.last_seen_utc
                FROM flows f
                JOIN apps a ON a.id = f.app_id
                {where}
                ORDER BY f.last_seen_utc DESC
                LIMIT $limit OFFSET $offset;
                """;

            AddRangeParameters(command, from, to, search);
            command.Parameters.AddWithValue("$limit", limit);
            command.Parameters.AddWithValue("$offset", offset);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                rows.Add(new HistoryRow
                {
                    AppDisplayName = reader.GetString(0),
                    AppPath = reader.GetString(1),
                    ProcessId = reader.GetInt32(2),
                    Protocol = reader.GetString(3),
                    LocalEndpoint = reader.GetString(4),
                    RemoteEndpoint = reader.GetString(5),
                    Direction = reader.GetString(6),
                    State = reader.GetString(7),
                    Quality = reader.GetString(8),
                    FirstSeenUtc = ParseStorage(reader.GetString(9)),
                    LastSeenUtc = ParseStorage(reader.GetString(10)),
                });
            }
        }

        return new HistoryPage
        {
            Rows = rows,
            TotalCount = total,
            DatabasePath = DatabasePath,
            QueriedUtc = DateTimeOffset.UtcNow,
        };
    }

    /// <summary>Deletes flows not seen within the retention window and apps without flows.</summary>
    public async Task<int> ApplyRetentionAsync(
        DateTimeOffset nowUtc,
        TimeSpan retention,
        CancellationToken cancellationToken = default)
    {
        if (retention <= TimeSpan.Zero)
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(retention, TimeSpan.Zero);
        }

        var cutoff = ToStorage(nowUtc.Subtract(retention));

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        int deleted;

        await using (var deleteFlows = connection.CreateCommand())
        {
            deleteFlows.CommandText = "DELETE FROM flows WHERE last_seen_utc < $cutoff;";
            deleteFlows.Parameters.AddWithValue("$cutoff", cutoff);
            deleted = await deleteFlows.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var deleteApps = connection.CreateCommand())
        {
            deleteApps.CommandText = "DELETE FROM apps WHERE id NOT IN (SELECT DISTINCT app_id FROM flows);";
            await deleteApps.ExecuteNonQueryAsync(cancellationToken);
        }

        return deleted;
    }

    private async Task MigrateAsync(CancellationToken cancellationToken)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await ExecuteAsync(connection, "PRAGMA journal_mode=WAL;", cancellationToken);
        await ExecuteAsync(connection, "PRAGMA foreign_keys=ON;", cancellationToken);
        await ExecuteAsync(connection, "PRAGMA busy_timeout=5000;", cancellationToken);
        await ExecuteAsync(connection, "PRAGMA synchronous=NORMAL;", cancellationToken);

        var integrity = await ExecuteScalarAsync(connection, "PRAGMA integrity_check;", cancellationToken);
        if (!string.Equals(integrity, "ok", StringComparison.OrdinalIgnoreCase))
        {
            throw new SqliteException("integrity_check failed", 26);
        }

        await ExecuteAsync(connection, SchemaSql, cancellationToken);

        var version = await ExecuteScalarAsync(connection, "SELECT MAX(version) FROM schema_migrations;", cancellationToken);
        if (!string.IsNullOrEmpty(version) &&
            int.Parse(version, CultureInfo.InvariantCulture) > SchemaVersion)
        {
            throw new InvalidOperationException(
                $"Database schema version {version} is newer than this build ({SchemaVersion}).");
        }

        await using var migration = connection.CreateCommand();
        migration.CommandText =
            "INSERT OR IGNORE INTO schema_migrations(version, applied_utc, checksum) VALUES ($version, $now, $checksum);";
        migration.Parameters.AddWithValue("$version", SchemaVersion);
        migration.Parameters.AddWithValue("$now", ToStorage(DateTimeOffset.UtcNow));
        migration.Parameters.AddWithValue("$checksum", SchemaChecksum);
        await migration.ExecuteNonQueryAsync(cancellationToken);
    }

    private void RecoverCorruptDatabase()
    {
        SqliteConnection.ClearAllPools();

        if (File.Exists(DatabasePath))
        {
            var backup = $"{DatabasePath}.corrupt-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}";
            File.Move(DatabasePath, backup, overwrite: true);
        }

        foreach (var suffix in new[] { "-wal", "-shm" })
        {
            var sidecar = DatabasePath + suffix;
            if (File.Exists(sidecar))
            {
                File.Delete(sidecar);
            }
        }
    }

    private static async Task<int> UpsertAppAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string key,
        LiveConnection flow,
        string now,
        CancellationToken cancellationToken)
    {
        await using (var upsert = connection.CreateCommand())
        {
            upsert.Transaction = transaction;
            upsert.CommandText = """
                INSERT INTO apps(app_key, display_name, executable_path, first_seen_utc, last_seen_utc)
                VALUES ($key, $name, $path, $now, $now)
                ON CONFLICT(app_key) DO UPDATE SET
                    display_name = excluded.display_name,
                    executable_path = excluded.executable_path,
                    last_seen_utc = excluded.last_seen_utc;
                """;
            upsert.Parameters.AddWithValue("$key", key);
            upsert.Parameters.AddWithValue("$name", flow.AppDisplayName);
            upsert.Parameters.AddWithValue("$path", flow.AppPath);
            upsert.Parameters.AddWithValue("$now", now);
            await upsert.ExecuteNonQueryAsync(cancellationToken);
        }

        await using var select = connection.CreateCommand();
        select.Transaction = transaction;
        select.CommandText = "SELECT id FROM apps WHERE app_key = $key;";
        select.Parameters.AddWithValue("$key", key);
        var id = await select.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(id, CultureInfo.InvariantCulture);
    }

    private static async Task UpsertFlowAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        int appId,
        LiveConnection flow,
        string now,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO flows(app_id, process_id, protocol, local_endpoint, remote_endpoint,
                              direction, state, quality, first_seen_utc, last_seen_utc)
            VALUES ($appId, $pid, $protocol, $local, $remote, $direction, $state, $quality, $now, $now)
            ON CONFLICT(app_id, protocol, local_endpoint, remote_endpoint, process_id) DO UPDATE SET
                last_seen_utc = excluded.last_seen_utc,
                state = excluded.state,
                direction = excluded.direction,
                quality = excluded.quality;
            """;
        command.Parameters.AddWithValue("$appId", appId);
        command.Parameters.AddWithValue("$pid", flow.ProcessId);
        command.Parameters.AddWithValue("$protocol", flow.Protocol.ToString());
        command.Parameters.AddWithValue("$local", flow.LocalEndpoint);
        command.Parameters.AddWithValue("$remote", flow.RemoteEndpoint);
        command.Parameters.AddWithValue("$direction", flow.Direction.ToString());
        command.Parameters.AddWithValue("$state", flow.State);
        command.Parameters.AddWithValue("$quality", flow.Quality.ToString());
        command.Parameters.AddWithValue("$now", now);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string AppKey(LiveConnection flow) =>
        flow.AppPath.Length > 0
            ? flow.AppPath
            : $"pid:{flow.ProcessId}:{flow.AppDisplayName}";

    private static void AddRangeParameters(SqliteCommand command, string from, string to, string? search)
    {
        command.Parameters.AddWithValue("$from", from);
        command.Parameters.AddWithValue("$to", to);
        command.Parameters.AddWithValue("$search", (object?)search ?? DBNull.Value);
    }

    private static string ToStorage(DateTimeOffset value) =>
        value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseStorage(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static string EscapeLike(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("%", "\\%", StringComparison.Ordinal)
            .Replace("_", "\\_", StringComparison.Ordinal);

    private static async Task ExecuteAsync(SqliteConnection connection, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<string?> ExecuteScalarAsync(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value?.ToString();
    }

    private static string SchemaChecksum { get; } = ComputeChecksum(SchemaSql);

    private static string ComputeChecksum(string schema)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(schema));
        return Convert.ToHexString(hash);
    }
}
