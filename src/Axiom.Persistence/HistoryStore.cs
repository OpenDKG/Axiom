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
    public const int SchemaVersion = 2;

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

    private string? _preOpenEvidenceDirectory;

    private bool _quarantined;

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
            DatabasePaths.EnsurePrivateDirectory(directory);
        }

        // An unclean shutdown leaves a WAL/journal that SQLite may checkpoint or delete while it
        // opens the database. Copy the database and every sidecar first so a later corruption
        // decision keeps the bytes exactly as they were before SQLite touched them.
        PreservePreOpenEvidence();

        // Quarantine an obviously non-SQLite file before opening it. SQLite may remove the WAL and
        // SHM sidecars while rejecting the file, losing evidence that belongs with the backup.
        if (File.Exists(DatabasePath) && !LooksLikeSqlite(DatabasePath))
        {
            try
            {
                RecoverCorruptDatabase();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // If Windows still holds the file, the SQLite open below reports the real error.
            }
        }
        else if (File.Exists(DatabasePath) && IsCorruptDatabase())
        {
            // A valid SQLite header does not mean the pages are valid. Probe read-only so the
            // original pages, WAL and SHM are still intact when they are quarantined.
            RecoverCorruptDatabase();
        }

        try
        {
            await MigrateAsync(cancellationToken);
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode is 11 or 26)
        {
            // 11 = SQLITE_CORRUPT, 26 = SQLITE_NOTADB. Both mean the file cannot be trusted.
            RecoverCorruptDatabase();
            await MigrateAsync(cancellationToken);
        }

        if (!_quarantined)
        {
            DiscardPreOpenEvidence();
        }
    }

    public async Task<int> UpsertAsync(ConnectionSnapshot snapshot, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var now = ToStorage(snapshot.CapturedUtc);
        // Windows paths are case-insensitive; Linux paths are not. Using one comparer on both
        // platforms merged /opt/App and /opt/app into a single history application on Linux.
        var appIds = new Dictionary<string, int>(
            OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
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

    /// <summary>Persists an owned firewall rule and one audit row in the same transaction.</summary>
    public async Task SaveFirewallRuleAsync(
        ManagedRule rule,
        string actorSid,
        string action,
        string result,
        string? error,
        RuleSpec? auditedSpec = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSid);

        var now = ToStorage(DateTimeOffset.UtcNow);
        var specJson = JsonSerializer.Serialize(rule.Spec, IpcJson.Options);
        // A failed update keeps the previous applied rule as durable intent, but the audit row must
        // show the specification the operator actually attempted.
        var auditSpecJson = auditedSpec is null ? specJson : JsonSerializer.Serialize(auditedSpec, IpcJson.Options);

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
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

        await InsertAuditAsync(connection, transaction, rule.ManagedRuleId, actorSid, action, result, auditSpecJson, error, now, cancellationToken);
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

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            // A failed removal leaves the rule in force in the kernel until the process exits, so
            // the stored state must not become Failed: startup restores Applied rules and would
            // otherwise silently drop an enforcement that is still active.
            update.CommandText = """
                UPDATE firewall_rules
                SET last_error = $error, updated_utc = $now
                WHERE managed_rule_id = $id;
                """;
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

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
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
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

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

    private static bool LooksLikeSqlite(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (stream.Length == 0)
            {
                return true;
            }

            if (stream.Length < 16)
            {
                return false;
            }

            Span<byte> header = stackalloc byte[16];
            return stream.Read(header) == header.Length &&
                   header.SequenceEqual("SQLite format 3\0"u8);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return true;
        }
    }

    /// <summary>
    /// Read-only integrity probe. It never writes the database file; a busy or locked database is
    /// left to the normal open so a second process cannot make us quarantine a healthy file.
    /// </summary>
    private bool IsCorruptDatabase()
    {
        try
        {
            var probe = new SqliteConnectionStringBuilder
            {
                DataSource = DatabasePath,
                Mode = SqliteOpenMode.ReadOnly,
                Cache = SqliteCacheMode.Private,
                Pooling = false,
            }.ToString();

            using var connection = new SqliteConnection(probe);
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA quick_check;";
            var result = command.ExecuteScalar() as string;
            return !string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase);
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode is 11 or 26)
        {
            return true;
        }
        catch (SqliteException)
        {
            return false;
        }
    }

    private void PreservePreOpenEvidence()
    {
        if (!File.Exists(DatabasePath) ||
            (!File.Exists(DatabasePath + "-wal") && !File.Exists(DatabasePath + "-journal")))
        {
            return;
        }

        try
        {
            var directory = Path.Combine(
                Path.GetDirectoryName(DatabasePath)!,
                "quarantine",
                $"preopen-{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);

            foreach (var suffix in new[] { string.Empty, "-wal", "-shm", "-journal" })
            {
                var source = DatabasePath + suffix;
                if (File.Exists(source))
                {
                    File.Copy(source, Path.Combine(directory, Path.GetFileName(source)));
                }
            }

            _preOpenEvidenceDirectory = directory;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Preserving evidence must never prevent the service from starting; the normal
            // quarantine below still moves whatever SQLite has not consumed.
            _ = exception;
        }
    }

    private void DiscardPreOpenEvidence()
    {
        if (_preOpenEvidenceDirectory is null)
        {
            return;
        }

        try
        {
            Directory.Delete(_preOpenEvidenceDirectory, recursive: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _ = exception;
        }

        _preOpenEvidenceDirectory = null;
    }

    private void RecoverCorruptDatabase()
    {
        _quarantined = true;
        SqliteConnection.ClearAllPools();

        var backup = $"{DatabasePath}.corrupt-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}";
        if (File.Exists(DatabasePath))
        {
            File.Move(DatabasePath, backup, overwrite: true);
        }

        // Keep the WAL and shared-memory files beside the quarantined database. They may contain
        // the only recoverable rows, and deleting them destroys forensic evidence.
        foreach (var suffix in new[] { "-wal", "-shm", "-journal" })
        {
            var sidecar = DatabasePath + suffix;
            if (File.Exists(sidecar))
            {
                File.Move(sidecar, backup + suffix, overwrite: true);
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
