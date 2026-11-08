// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Axiom.Contracts.Agents;

namespace Axiom.Persistence;

/// <summary>
/// Reads host-owned Claude session descriptors, Codex thread metadata and OpenCode/OpenChamber
/// session rows. Read-only, bounded and fail-open; it never writes to the agent databases or
/// stores raw session identifiers in the UI.
/// </summary>
public sealed class AgentSessionReader : IAgentSessionSource
{
    private static readonly TimeSpan ActiveWindow = TimeSpan.FromMinutes(5);

    private static readonly TimeSpan HistoryWindow = TimeSpan.FromDays(7);

    private readonly string _userProfile;

    private readonly string? _claudeHome;

    private readonly string? _codexHome;

    private readonly string? _opencodeDb;

    public AgentSessionReader(
        string? userProfile = null,
        string? claudeHome = null,
        string? codexHome = null,
        string? opencodeDb = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _claudeHome = claudeHome;
        _codexHome = codexHome;
        _opencodeDb = opencodeDb;
    }

    public IReadOnlyList<AgentSessionInfo> Read()
    {
        var result = new List<AgentSessionInfo>();
        try
        {
            result.AddRange(ReadClaude());
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
        }

        try
        {
            result.AddRange(ReadCodex());
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or SqliteException)
        {
        }

        try
        {
            result.AddRange(ReadOpenCode());
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SqliteException)
        {
        }

        return result
            .OrderByDescending(item => item.LastSeenUtc)
            .Take(30)
            .ToArray();
    }

    private IEnumerable<AgentSessionInfo> ReadClaude()
    {
        var configured = Environment.GetEnvironmentVariable("CLAUDE_CONFIG_DIR");
        var home = _claudeHome ?? (string.IsNullOrWhiteSpace(configured)
            ? Path.Combine(_userProfile, ".claude")
            : configured);
        var directory = Path.Combine(home, "sessions");
        if (!Directory.Exists(directory))
        {
            yield break;
        }

        var now = DateTimeOffset.UtcNow;
        foreach (var path in Directory.EnumerateFiles(directory, "*.json")
                     .OrderByDescending(File.GetLastWriteTimeUtc)
                     .Take(40))
        {
            AgentSessionInfo? session = null;
            try
            {
                using var document = JsonDocument.Parse(File.ReadAllText(path));
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var kind = ReadString(root, "kind");
                if (!string.IsNullOrWhiteSpace(kind) &&
                    !string.Equals(kind, "interactive", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var id = ReadString(root, "sessionId");
                if (string.IsNullOrWhiteSpace(id))
                {
                    continue;
                }

                var pid = ReadInt(root, "pid");
                var live = false;
                if (pid > 0)
                {
                    try
                    {
                        using var process = Process.GetProcessById(pid);
                        live = !process.HasExited;
                    }
                    catch (ArgumentException)
                    {
                    }
                    catch (InvalidOperationException)
                    {
                    }
                }

                var lastSeen = new DateTimeOffset(File.GetLastWriteTimeUtc(path));
                live |= now - lastSeen <= ActiveWindow;
                if (!live && now - lastSeen > HistoryWindow)
                {
                    continue;
                }

                session = new AgentSessionInfo(
                    "claude",
                    SessionKey("claude", id),
                    Truncate(ReadString(root, "name"), 120),
                    ReadString(root, "cwd") ?? string.Empty,
                    lastSeen,
                    live);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
            {
            }

            if (session is not null)
            {
                yield return session;
            }
        }
    }

    private IEnumerable<AgentSessionInfo> ReadCodex()
    {
        var configured = Environment.GetEnvironmentVariable("CODEX_HOME");
        var home = _codexHome ?? (string.IsNullOrWhiteSpace(configured)
            ? Path.Combine(_userProfile, ".codex")
            : configured);
        var candidates = new List<string>();
        if (Directory.Exists(home))
        {
            candidates.AddRange(Directory.EnumerateFiles(home, "state_*.sqlite"));
        }

        var sqlite = Path.Combine(home, "sqlite");
        if (Directory.Exists(sqlite))
        {
            candidates.AddRange(Directory.EnumerateFiles(sqlite, "state_*.sqlite"));
        }

        var now = DateTimeOffset.UtcNow;
        foreach (var path in candidates
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(File.GetLastWriteTimeUtc)
                     .Take(3))
        {
            foreach (var session in ReadCodexDatabase(path, now))
            {
                yield return session;
            }
        }
    }

    private static IEnumerable<AgentSessionInfo> ReadCodexDatabase(
        string path,
        DateTimeOffset now)
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadOnly,
            DefaultTimeout = 1,
            Pooling = false,
        }.ToString();

        using var connection = new SqliteConnection(connectionString);
        connection.Open();
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var schema = connection.CreateCommand())
        {
            schema.CommandText = "PRAGMA table_info(threads)";
            using var reader = schema.ExecuteReader();
            while (reader.Read())
            {
                columns.Add(reader.GetString(1));
            }
        }

        if (!columns.Contains("id") || (!columns.Contains("title") && !columns.Contains("name")))
        {
            yield break;
        }

        var titleColumn = columns.Contains("name") && columns.Contains("title")
            ? "COALESCE(NULLIF(name, ''), title)"
            : columns.Contains("name") ? "name" : "title";
        var updatedColumn = columns.Contains("updated_at_ms") ? "updated_at_ms" : "updated_at";
        var workspaceColumn = columns.Contains("cwd") ? "cwd" : "NULL";
        var query = connection.CreateCommand();
        query.CommandText =
            $"SELECT id, {titleColumn}, {workspaceColumn}, {updatedColumn} FROM threads " +
            "ORDER BY " + updatedColumn + " DESC LIMIT 16";
        using var rows = query.ExecuteReader();
        while (rows.Read())
        {
            if (rows.IsDBNull(0))
            {
                continue;
            }

            var id = rows.GetString(0);
            var title = rows.IsDBNull(1) ? string.Empty : rows.GetString(1);
            var workspace = rows.IsDBNull(2) ? string.Empty : rows.GetString(2);
            var raw = rows.IsDBNull(3) ? 0L : rows.GetInt64(3);
            var lastSeen = updatedColumn == "updated_at_ms"
                ? DateTimeOffset.FromUnixTimeMilliseconds(raw <= 0 ? 0 : raw)
                : DateTimeOffset.FromUnixTimeSeconds(raw <= 0 ? 0 : raw);
            var live = now - lastSeen <= ActiveWindow;
            if (!live && now - lastSeen > HistoryWindow)
            {
                continue;
            }

            yield return new AgentSessionInfo(
                "codex",
                SessionKey("codex", id),
                Truncate(title, 120),
                workspace,
                lastSeen,
                live);
        }
    }

    private IEnumerable<AgentSessionInfo> ReadOpenCode()
    {
        var path = _opencodeDb ?? Path.Combine(
            _userProfile,
            ".local",
            "share",
            "opencode",
            "opencode.db");
        if (!File.Exists(path))
        {
            yield break;
        }

        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadOnly,
            DefaultTimeout = 1,
            Pooling = false,
        }.ToString();

        using var connection = new SqliteConnection(connectionString);
        connection.Open();

        var table = TableExists(connection, "session_v2")
            ? "session_v2"
            : TableExists(connection, "session") ? "session" : null;
        if (table is null)
        {
            yield break;
        }

        var columns = ReadColumns(connection, table);
        if (!columns.Contains("id") || !columns.Contains("time_updated"))
        {
            yield break;
        }

        var titleParts = new List<string>();
        if (columns.Contains("title"))
        {
            titleParts.Add("NULLIF(title, '')");
        }

        if (columns.Contains("slug"))
        {
            titleParts.Add("NULLIF(slug, '')");
        }

        titleParts.Add("'OpenCode session'");
        var titleColumn = "COALESCE(" + string.Join(", ", titleParts) + ")";
        var directoryColumn = columns.Contains("directory") ? "directory" : "''";
        var archivedFilter = columns.Contains("time_archived")
            ? "WHERE time_archived IS NULL OR time_archived = 0"
            : string.Empty;
        var query = connection.CreateCommand();
        query.CommandText =
            $"SELECT id, {titleColumn}, {directoryColumn}, time_updated FROM {table} " +
            $"{archivedFilter} ORDER BY time_updated DESC LIMIT 16";

        var now = DateTimeOffset.UtcNow;
        using var rows = query.ExecuteReader();
        while (rows.Read())
        {
            if (rows.IsDBNull(0))
            {
                continue;
            }

            var raw = rows.IsDBNull(3) ? 0L : rows.GetInt64(3);
            if (raw <= 0)
            {
                continue;
            }

            var lastSeen = DateTimeOffset.FromUnixTimeMilliseconds(raw);
            var live = now - lastSeen <= ActiveWindow;
            if (!live && now - lastSeen > HistoryWindow)
            {
                continue;
            }

            yield return new AgentSessionInfo(
                "opencode",
                SessionKey("opencode", rows.GetString(0)),
                Truncate(rows.IsDBNull(1) ? null : rows.GetString(1), 120),
                rows.IsDBNull(2) ? string.Empty : rows.GetString(2),
                lastSeen,
                live);
        }
    }

    private static bool TableExists(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = $name LIMIT 1";
        command.Parameters.AddWithValue("$name", table);
        return command.ExecuteScalar() is not null;
    }

    private static HashSet<string> ReadColumns(SqliteConnection connection, string table)
    {
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info({table})";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            columns.Add(reader.GetString(1));
        }

        return columns;
    }

    private static string SessionKey(string framework, string id)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(framework + "\0" + id));
        return Convert.ToHexString(digest)[..24].ToLowerInvariant();
    }

    private static string? ReadString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static int ReadInt(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.Number &&
        value.TryGetInt32(out var number)
            ? number
            : 0;

    private static string Truncate(string? value, int max) =>
        string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim()[..Math.Min(value.Trim().Length, max)];
}
