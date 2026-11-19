// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.History;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Microsoft.Data.Sqlite;

namespace Axiom.Persistence;

/// <summary>
/// Local SQLite history of observed flows (FND-005). WAL, UTC timestamps, upsert by flow key,
/// retention and time-window queries. Byte buckets are created for FND-004 but stay unused.
/// </summary>
public sealed class HistoryStore
{
    public const int SchemaVersion = 3;

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

        CREATE TABLE IF NOT EXISTS throughput_buckets (
            bucket_start_unix INTEGER NOT NULL PRIMARY KEY,
            upload_bytes      INTEGER NOT NULL DEFAULT 0,
            download_bytes    INTEGER NOT NULL DEFAULT 0,
            measured_seconds  REAL    NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS firewall_rules (
            managed_rule_id  TEXT    NOT NULL PRIMARY KEY,
            os_rule_name     TEXT    NOT NULL,
            spec_json        TEXT    NOT NULL,
            state            INTEGER NOT NULL,
            last_verified_utc TEXT,
            last_error       TEXT,
            updated_utc      TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rule_audit (
            id              INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            managed_rule_id TEXT    NOT NULL,
            actor_sid       TEXT    NOT NULL,
            timestamp_utc   TEXT    NOT NULL,
            action          TEXT    NOT NULL,
            result          TEXT    NOT NULL,
            old_json        TEXT,
            new_json        TEXT,
            error           TEXT
        );

        CREATE INDEX IF NOT EXISTS ix_rule_audit_rule ON rule_audit(managed_rule_id);
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

        RestrictUnixPermissions();
    }

    /// <summary>
    /// History is private to the service account: on Unix the database and its WAL/shared-memory
    /// side files are 0600 (SQLite creates new side files with the database's mode, so setting
    /// the database once covers later ones). No-op on Windows.
    /// </summary>
    private void RestrictUnixPermissions()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        foreach (var suffix in new[] { string.Empty, "-wal", "-shm", "-journal" })
        {
            var path = DatabasePath + suffix;
            try
            {
                if (File.Exists(path))
                {
                    File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // Best effort; the daemon's startup sweep repeats it.
            }
        }
    }

    /// <summary>
    /// Opens a pooled connection with the pragmas that keep routine writes cheap. SQLite applies
    /// synchronous/journal settings per connection, so a pooled connection that was never
    /// configured would silently fall back to a full fsync on every commit.
    /// </summary>
    private async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(connection, "PRAGMA busy_timeout=5000;", cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(connection, "PRAGMA synchronous=NORMAL;", cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(connection, "PRAGMA temp_store=MEMORY;", cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(connection, "PRAGMA cache_size=-8192;", cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(connection, "PRAGMA wal_autocheckpoint=2000;", cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
    private readonly Dictionary<string, (string Fingerprint, string CapturedUtc)> _writtenFlows = new(StringComparer.Ordinal);

    private DateTimeOffset _lastFullRefresh = DateTimeOffset.MinValue;

    /// <summary>
    /// Refreshes last-seen timestamps on each distinct snapshot capture while suppressing duplicate
    /// writes for identical snapshot timestamps.
    /// </summary>
    private static readonly TimeSpan FullRefreshInterval = TimeSpan.FromHours(6);

    public async Task<int> UpsertAsync(ConnectionSnapshot snapshot, bool forceRefresh = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var now = ToStorage(snapshot.CapturedUtc);
        bool refreshAll;
        var changed = new List<(LiveConnection Flow, string Key, string Fingerprint)>();
        lock (_writtenFlows)
        {
            refreshAll = forceRefresh || DateTimeOffset.UtcNow - _lastFullRefresh >= FullRefreshInterval;
            foreach (var flow in snapshot.Connections)
            {
                var key = FlowKey(flow);
                var fingerprint = FlowFingerprint(flow);
                if (refreshAll ||
                    !_writtenFlows.TryGetValue(key, out var previous) ||
                    !string.Equals(previous.Fingerprint, fingerprint, StringComparison.Ordinal) ||
                    !string.Equals(previous.CapturedUtc, now, StringComparison.Ordinal))
                {
                    changed.Add((flow, key, fingerprint));
                }
            }
        }

        if (changed.Count == 0)
        {
            return 0;
        }

        var appIds = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var (flow, _, _) in changed)
        {
            var key = AppKey(flow);
            if (!appIds.ContainsKey(key))
            {
                appIds[key] = 0;
            }
        }

        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        foreach (var (flow, _, _) in changed)
        {
            var key = AppKey(flow);
            if (appIds[key] == 0)
            {
                appIds[key] = await UpsertAppAsync(connection, transaction, key, flow, now, cancellationToken);
            }

            await UpsertFlowAsync(connection, transaction, appIds[key], flow, now, cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);

        lock (_writtenFlows)
        {
            if (refreshAll)
            {
                _writtenFlows.Clear();
                _lastFullRefresh = DateTimeOffset.UtcNow;
            }

            foreach (var (_, key, fingerprint) in changed)
            {
                _writtenFlows[key] = (fingerprint, now);
            }

            if (_writtenFlows.Count > 20_000)
            {
                _writtenFlows.Clear();
            }
        }

        return changed.Count;
    }

    private static string FlowKey(LiveConnection flow) =>
        string.Join(
            '\u001f',
            AppKey(flow),
            flow.Protocol.ToString(),
            LocalHost(flow.LocalEndpoint),
            flow.RemoteEndpoint,
            flow.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));

    private static string FlowFingerprint(LiveConnection flow) =>
        string.Join(
            '\u001f',
            flow.State,
            flow.Direction.ToString(),
            flow.Quality.ToString());

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

        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

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

        var baseline = query.IncludeBaseline
            ? await QueryBaselineAsync(connection, where, from, to, search, total, cancellationToken)
                  .ConfigureAwait(false)
            : null;

        return new HistoryPage
        {
            Rows = rows,
            TotalCount = total,
            DatabasePath = DatabasePath,
            QueriedUtc = DateTimeOffset.UtcNow,
            Baseline = baseline,
        };
    }

    /// <summary>
    /// Stores the absolute byte totals observed for one minute. The sampler owns the minute
    /// accumulator, so writing the same bucket again replaces its partial value.
    /// </summary>
    public Task RecordThroughputAsync(
        DateTimeOffset bucketStartUtc,
        long uploadBytes,
        long downloadBytes,
        double measuredSeconds,
        CancellationToken cancellationToken = default) =>
        RecordThroughputBatchAsync(
            [new ThroughputBucket(bucketStartUtc, uploadBytes, downloadBytes, measuredSeconds)],
            cancellationToken);

    /// <summary>Writes several minute buckets in one transaction, so batching keeps commits rare.</summary>
    public async Task RecordThroughputBatchAsync(
        IReadOnlyList<ThroughputBucket> buckets,
        CancellationToken cancellationToken = default)
    {
        if (buckets.Count == 0)
        {
            return;
        }

        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        foreach (var bucket in buckets)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO throughput_buckets(bucket_start_unix, upload_bytes, download_bytes, measured_seconds)
                VALUES ($bucket, $upload, $download, $measured)
                ON CONFLICT(bucket_start_unix) DO UPDATE SET
                    upload_bytes = excluded.upload_bytes,
                    download_bytes = excluded.download_bytes,
                    measured_seconds = excluded.measured_seconds;
                """;
            command.Parameters.AddWithValue("$bucket", bucket.StartUtc.ToUnixTimeSeconds());
            command.Parameters.AddWithValue("$upload", bucket.UploadBytes);
            command.Parameters.AddWithValue("$download", bucket.DownloadBytes);
            command.Parameters.AddWithValue("$measured", bucket.MeasuredSeconds);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    /// <summary>
    /// Aggregates persisted throughput into contiguous buckets. Buckets without a measurement stay
    /// present with zero bytes and zero measured seconds so a chart can draw a gap instead of
    /// pretending the network was idle.
    /// </summary>
    public async Task<ThroughputHistory> QueryThroughputAsync(
        ThroughputHistoryQuery query,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        var windowSeconds = Math.Max(60, (long)(query.ToUtc - query.FromUtc).TotalSeconds);
        var bucketSeconds = Math.Clamp(query.BucketSeconds, 60, 21_600);

        // Keep the response bounded even if a caller asks for a month of minute rows.
        while (windowSeconds / bucketSeconds > 2_000)
        {
            bucketSeconds *= 2;
        }

        var fromUnix = query.FromUtc.ToUnixTimeSeconds() / bucketSeconds * bucketSeconds;
        var toUnix = Math.Max(fromUnix, query.ToUtc.ToUnixTimeSeconds());

        var measured = new Dictionary<long, (long Upload, long Download, double Seconds)>();
        await using (var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false))
        {
            await using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT (bucket_start_unix / $bucket) * $bucket AS start_unix,
                       SUM(upload_bytes),
                       SUM(download_bytes),
                       SUM(measured_seconds)
                FROM throughput_buckets
                WHERE bucket_start_unix >= $from AND bucket_start_unix <= $to
                GROUP BY start_unix
                ORDER BY start_unix;
                """;
            command.Parameters.AddWithValue("$bucket", bucketSeconds);
            command.Parameters.AddWithValue("$from", fromUnix);
            command.Parameters.AddWithValue("$to", toUnix);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                measured[reader.GetInt64(0)] = (reader.GetInt64(1), reader.GetInt64(2), reader.GetDouble(3));
            }
        }

        var points = new List<ThroughputPoint>();
        for (var start = fromUnix; start <= toUnix; start += bucketSeconds)
        {
            var values = measured.GetValueOrDefault(start);
            points.Add(new ThroughputPoint
            {
                StartUtc = DateTimeOffset.FromUnixTimeSeconds(start),
                UploadBytes = values.Upload,
                DownloadBytes = values.Download,
                MeasuredSeconds = values.Seconds,
            });
        }

        return new ThroughputHistory
        {
            Points = points,
            BucketSeconds = bucketSeconds,
            QueriedUtc = DateTimeOffset.UtcNow,
            Detail = "Recorded by the Axiom service; history starts when the service first ran.",
        };
    }

    private static async Task<HistoryBaseline> QueryBaselineAsync(
        SqliteConnection connection,
        string where,
        string from,
        string to,
        string? search,
        int totalFlows,
        CancellationToken cancellationToken)
    {
        var apps = new List<HistoryBaselineApp>();
        var flows = new List<HistoryBaselineFlow>();
        var remotes = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        await using (var command = connection.CreateCommand())
        {
            command.CommandText = $"""
                WITH ranked AS (
                    SELECT a.app_key,
                           f.remote_endpoint,
                           COUNT(*) AS cnt,
                           ROW_NUMBER() OVER (
                               PARTITION BY a.app_key
                               ORDER BY COUNT(*) DESC, f.remote_endpoint ASC) AS rn
                    FROM flows f
                    JOIN apps a ON a.id = f.app_id
                    {where}
                    GROUP BY a.app_key, f.remote_endpoint
                )
                SELECT app_key, remote_endpoint
                FROM ranked
                WHERE rn <= 3
                ORDER BY app_key, rn;
                """;
            AddRangeParameters(command, from, to, search);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var appKey = reader.GetString(0);
                if (!remotes.TryGetValue(appKey, out var list))
                {
                    list = [];
                    remotes[appKey] = list;
                }

                list.Add(reader.GetString(1));
            }
        }

        await using (var command = connection.CreateCommand())
        {
            command.CommandText = $"""
                SELECT a.app_key,
                       a.display_name,
                       a.executable_path,
                       COUNT(*) AS row_count,
                       MIN(f.first_seen_utc),
                       MAX(f.last_seen_utc)
                FROM flows f
                JOIN apps a ON a.id = f.app_id
                {where}
                GROUP BY a.app_key
                ORDER BY row_count DESC
                LIMIT 200;
                """;
            AddRangeParameters(command, from, to, search);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var appKey = reader.GetString(0);
                apps.Add(new HistoryBaselineApp(
                    appKey,
                    reader.GetString(1),
                    reader.GetString(2),
                    (int)reader.GetInt64(3),
                    ParseStorage(reader.GetString(4)),
                    ParseStorage(reader.GetString(5)),
                    remotes.TryGetValue(appKey, out var list) ? list : []));
            }
        }

        await using (var command = connection.CreateCommand())
        {
            command.CommandText = $"""
                SELECT a.app_key,
                       f.protocol,
                       f.remote_endpoint,
                       f.direction,
                       COUNT(*) AS row_count,
                       MIN(f.first_seen_utc),
                       MAX(f.last_seen_utc)
                FROM flows f
                JOIN apps a ON a.id = f.app_id
                {where}
                GROUP BY a.app_key, f.protocol, f.remote_endpoint, f.direction
                ORDER BY row_count DESC
                LIMIT 5000;
                """;
            AddRangeParameters(command, from, to, search);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                flows.Add(new HistoryBaselineFlow(
                    reader.GetString(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    reader.GetString(3),
                    (int)reader.GetInt64(4),
                    ParseStorage(reader.GetString(5)),
                    ParseStorage(reader.GetString(6))));
            }
        }

        return new HistoryBaseline(
            apps,
            flows,
            totalFlows,
            DateTimeOffset.UtcNow,
            "Aggregated local flow history. It records observed flow rows, not packet counts, " +
            "payloads or byte volumes.");
    }

    /// <summary>Persists an owned firewall rule and one audit row in the same transaction.</summary>
    public async Task SaveFirewallRuleAsync(
        ManagedRule rule,
        string actorSid,
        string action,
        string result,
        string? error,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSid);

        var now = ToStorage(DateTimeOffset.UtcNow);
        var specJson = JsonSerializer.Serialize(rule.Spec, IpcJson.Options);

        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await using (var upsert = connection.CreateCommand())
        {
            upsert.Transaction = transaction;
            upsert.CommandText = """
                INSERT INTO firewall_rules(managed_rule_id, os_rule_name, spec_json, state,
                                           last_verified_utc, last_error, updated_utc)
                VALUES ($id, $name, $spec, $state, $verified, $error, $now)
                ON CONFLICT(managed_rule_id) DO UPDATE SET
                    os_rule_name = excluded.os_rule_name,
                    spec_json = excluded.spec_json,
                    state = excluded.state,
                    last_verified_utc = excluded.last_verified_utc,
                    last_error = excluded.last_error,
                    updated_utc = excluded.updated_utc;
                """;
            upsert.Parameters.AddWithValue("$id", rule.ManagedRuleId.ToString("D"));
            upsert.Parameters.AddWithValue("$name", rule.OsRuleName);
            upsert.Parameters.AddWithValue("$spec", specJson);
            upsert.Parameters.AddWithValue("$state", (int)rule.State);
            upsert.Parameters.AddWithValue("$verified", (object?)ToStorageOrNull(rule.LastVerifiedUtc) ?? DBNull.Value);
            upsert.Parameters.AddWithValue("$error", (object?)rule.LastErrorCode ?? DBNull.Value);
            upsert.Parameters.AddWithValue("$now", now);
            await upsert.ExecuteNonQueryAsync(cancellationToken);
        }

        await InsertAuditAsync(connection, transaction, rule.ManagedRuleId, actorSid, action, result, specJson, error, now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    /// <summary>
    /// Records a failed removal without deleting the stored intent. The OS rule may still be
    /// present, so the durable state becomes Failed and the actor/error is audited in the same
    /// transaction.
    /// </summary>
    public async Task RecordFirewallRuleRemovalFailureAsync(
        Guid managedRuleId,
        string actorSid,
        string? errorCode,
        string? errorMessage,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSid);

        var now = ToStorage(DateTimeOffset.UtcNow);

        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE firewall_rules
                SET state = $state, last_error = $error, updated_utc = $now
                WHERE managed_rule_id = $id;
                """;
            update.Parameters.AddWithValue("$state", (int)RuleState.Failed);
            update.Parameters.AddWithValue("$error", (object?)errorCode ?? DBNull.Value);
            update.Parameters.AddWithValue("$now", now);
            update.Parameters.AddWithValue("$id", managedRuleId.ToString("D"));
            await update.ExecuteNonQueryAsync(cancellationToken);
        }

        await InsertAuditAsync(
            connection,
            transaction,
            managedRuleId,
            actorSid,
            "rule.remove",
            "failed",
            newJson: null,
            error: errorMessage ?? errorCode,
            now,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task DeleteFirewallRuleAsync(
        Guid managedRuleId,
        string actorSid,
        string result,
        string? error,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSid);

        var now = ToStorage(DateTimeOffset.UtcNow);

        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM firewall_rules WHERE managed_rule_id = $id;";
            delete.Parameters.AddWithValue("$id", managedRuleId.ToString("D"));
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }

        await InsertAuditAsync(connection, transaction, managedRuleId, actorSid, "rule.remove", result, null, error, now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<ManagedRule>> ListFirewallRulesAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT managed_rule_id, os_rule_name, spec_json, state, last_verified_utc, last_error
            FROM firewall_rules
            ORDER BY updated_utc DESC;
            """;

        var rules = new List<ManagedRule>();

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var spec = JsonSerializer.Deserialize<RuleSpec>(reader.GetString(2), IpcJson.Options);
            if (spec is null)
            {
                continue;
            }

            rules.Add(new ManagedRule
            {
                ManagedRuleId = Guid.Parse(reader.GetString(0)),
                OsRuleName = reader.GetString(1),
                Spec = spec,
                State = (RuleState)reader.GetInt32(3),
                LastVerifiedUtc = reader.IsDBNull(4) ? null : ParseStorage(reader.GetString(4)),
                LastErrorCode = reader.IsDBNull(5) ? null : reader.GetString(5),
            });
        }

        return rules;
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

        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

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

        await using (var deleteThroughput = connection.CreateCommand())
        {
            deleteThroughput.CommandText =
                "DELETE FROM throughput_buckets WHERE bucket_start_unix < $cutoff;";
            deleteThroughput.Parameters.AddWithValue(
                "$cutoff",
                nowUtc.Subtract(retention).ToUnixTimeSeconds());
            await deleteThroughput.ExecuteNonQueryAsync(cancellationToken);
        }

        // Reclaim WAL growth and shrink the database file once substantial dead pages accumulate.
        await ExecuteAsync(connection, "PRAGMA wal_checkpoint(TRUNCATE);", cancellationToken);
        var freelistText = await ExecuteScalarAsync(connection, "PRAGMA freelist_count;", cancellationToken);
        if (long.TryParse(freelistText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var freelistPages) &&
            freelistPages >= 1024)
        {
            await ExecuteAsync(connection, "VACUUM;", cancellationToken);
            await ExecuteAsync(connection, "PRAGMA wal_checkpoint(TRUNCATE);", cancellationToken);
        }

        return deleted;
    }

    private async Task MigrateAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

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
        command.Parameters.AddWithValue("$local", LocalHost(flow.LocalEndpoint));
        command.Parameters.AddWithValue("$remote", flow.RemoteEndpoint);
        command.Parameters.AddWithValue("$direction", flow.Direction.ToString());
        command.Parameters.AddWithValue("$state", flow.State);
        command.Parameters.AddWithValue("$quality", flow.Quality.ToString());
        command.Parameters.AddWithValue("$now", now);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>
    /// History is grouped by remote endpoint, so the local port carries no information and would
    /// create a new row for every short-lived connection. Keep the local address only.
    /// </summary>
    private static string LocalHost(string endpoint)
    {
        if (string.IsNullOrEmpty(endpoint))
        {
            return string.Empty;
        }

        if (endpoint[0] == '[')
        {
            var closing = endpoint.IndexOf(']');
            return closing > 1 ? endpoint[1..closing] : endpoint;
        }

        var colon = endpoint.LastIndexOf(':');
        return colon > 0 && endpoint.IndexOf(':') == colon ? endpoint[..colon] : endpoint;
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

    private static string? ToStorageOrNull(DateTimeOffset? value) =>
        value is null ? null : ToStorage(value.Value);

    private static async Task InsertAuditAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid managedRuleId,
        string actorSid,
        string action,
        string result,
        string? newJson,
        string? error,
        string now,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO rule_audit(managed_rule_id, actor_sid, timestamp_utc, action, result,
                                   old_json, new_json, error)
            VALUES ($id, $actor, $now, $action, $result, NULL, $new, $error);
            """;
        command.Parameters.AddWithValue("$id", managedRuleId.ToString("D"));
        command.Parameters.AddWithValue("$actor", actorSid);
        command.Parameters.AddWithValue("$now", now);
        command.Parameters.AddWithValue("$action", action);
        command.Parameters.AddWithValue("$result", result);
        command.Parameters.AddWithValue("$new", (object?)newJson ?? DBNull.Value);
        command.Parameters.AddWithValue("$error", (object?)error ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

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
