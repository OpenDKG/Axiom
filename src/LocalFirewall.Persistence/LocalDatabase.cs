// SPDX-License-Identifier: GPL-3.0-or-later
using Microsoft.Data.Sqlite;

namespace LocalFirewall.Persistence;

/// <summary>Result of opening and initialising the local database.</summary>
public sealed record DatabaseHealth(
    bool IsHealthy,
    string JournalMode,
    bool ForeignKeysEnabled,
    int SchemaVersion,
    long FileSizeBytes,
    string Detail);

/// <summary>
/// Minimal SQLite bootstrap used from FND-005 onwards: WAL journal, foreign keys, a migration
/// table and an integrity check. It creates only its own database file; it never touches the
/// Windows firewall or any OS configuration.
/// </summary>
public sealed class LocalDatabase(string databasePath)
{
    public const int BaselineSchemaVersion = 0;

    private const string BootstrapSql = """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version     INTEGER NOT NULL PRIMARY KEY,
            applied_utc TEXT    NOT NULL,
            checksum    TEXT    NOT NULL
        );
        """;

    public string DatabasePath { get; } = ValidatePath(databasePath);

    public async Task<DatabaseHealth> InitializeAsync(CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(DatabasePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            ForeignKeys = true,
        }.ToString();

        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        var journalMode = await ExecuteScalarAsync(connection, "PRAGMA journal_mode=WAL;", cancellationToken);
        await ExecuteNonQueryAsync(connection, "PRAGMA foreign_keys=ON;", cancellationToken);
        await ExecuteNonQueryAsync(connection, "PRAGMA busy_timeout=5000;", cancellationToken);
        await ExecuteNonQueryAsync(connection, "PRAGMA synchronous=NORMAL;", cancellationToken);
        await ExecuteNonQueryAsync(connection, BootstrapSql, cancellationToken);

        var foreignKeys = await ExecuteScalarAsync(connection, "PRAGMA foreign_keys;", cancellationToken);
        var schemaVersion = await ExecuteScalarAsync(connection, "SELECT MAX(version) FROM schema_migrations;", cancellationToken);
        var integrity = await ExecuteScalarAsync(connection, "PRAGMA integrity_check;", cancellationToken);

        var version = string.IsNullOrEmpty(schemaVersion)
            ? BaselineSchemaVersion
            : int.Parse(schemaVersion, System.Globalization.CultureInfo.InvariantCulture);

        var isHealthy = string.Equals(integrity, "ok", StringComparison.OrdinalIgnoreCase);

        return new DatabaseHealth(
            IsHealthy: isHealthy,
            JournalMode: journalMode ?? "unknown",
            ForeignKeysEnabled: string.Equals(foreignKeys, "1", StringComparison.Ordinal),
            SchemaVersion: version,
            FileSizeBytes: File.Exists(DatabasePath) ? new FileInfo(DatabasePath).Length : 0,
            Detail: isHealthy ? "integrity_check=ok" : $"integrity_check={integrity}");
    }

    private static async Task<string?> ExecuteScalarAsync(SqliteConnection connection, string sql, CancellationToken ct)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        var value = await command.ExecuteScalarAsync(ct);
        return value?.ToString();
    }

    private static async Task ExecuteNonQueryAsync(SqliteConnection connection, string sql, CancellationToken ct)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(ct);
    }

    private static string ValidatePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new ArgumentException("Database path must be absolute.", nameof(path));
        }

        return path;
    }
}
