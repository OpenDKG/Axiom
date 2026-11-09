// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Microsoft.Data.Sqlite;
using Axiom.Persistence;
using Xunit;

namespace Axiom.Persistence.Tests;

public sealed class AgentSessionReaderTests
{
    [Fact]
    public void Reads_Claude_host_session_descriptor_without_exposing_the_raw_id()
    {
        var root = NewRoot();
        try
        {
            var sessions = Path.Combine(root, ".claude", "sessions");
            Directory.CreateDirectory(sessions);
            File.WriteAllText(
                Path.Combine(sessions, "session.json"),
                """
                {
                  "sessionId": "claude-secret-session-id",
                  "kind": "interactive",
                  "name": "Checkout repair",
                  "cwd": "C:\\work\\checkout",
                  "pid": 0
                }
                """);

            var rows = new AgentSessionReader(root, Path.Combine(root, ".claude"), Path.Combine(root, ".codex")).Read();

            var row = Assert.Single(rows);
            Assert.Equal("claude", row.Framework);
            Assert.Equal("Checkout repair", row.Title);
            Assert.Equal("C:\\work\\checkout", row.Workspace);
            Assert.Equal(24, row.SessionKey.Length);
            Assert.DoesNotContain("claude-secret-session-id", row.SessionKey, StringComparison.Ordinal);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Reads_Codex_thread_title_from_state_database()
    {
        var root = NewRoot();
        try
        {
            var codex = Path.Combine(root, ".codex");
            Directory.CreateDirectory(codex);
            var database = Path.Combine(codex, "state_1.sqlite");
            using (var connection = new SqliteConnection($"Data Source={database}"))
            {
                connection.Open();
                using var create = connection.CreateCommand();
                create.CommandText = """
                    CREATE TABLE threads (
                        id TEXT PRIMARY KEY,
                        title TEXT,
                        name TEXT,
                        cwd TEXT,
                        updated_at INTEGER,
                        archived INTEGER DEFAULT 0
                    );
                    INSERT INTO threads(id, title, name, cwd, updated_at, archived)
                    VALUES ('codex-session-id', 'Generated title', 'Host task name', 'C:\work\api', strftime('%s','now'), 0);
                    """;
                create.ExecuteNonQuery();
            }

            var rows = new AgentSessionReader(root, Path.Combine(root, ".claude"), Path.Combine(root, ".codex")).Read();

            var row = Assert.Single(rows);
            Assert.Equal("codex", row.Framework);
            Assert.Equal("Host task name", row.Title);
            Assert.Equal("C:\\work\\api", row.Workspace);
            Assert.Equal(24, row.SessionKey.Length);
            Assert.DoesNotContain("codex-session-id", row.SessionKey, StringComparison.Ordinal);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Reads_OpenCode_sessions_and_marks_the_recent_one_live()
    {
        var root = NewRoot();
        try
        {
            var database = Path.Combine(root, "opencode.db");
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            using (var connection = new SqliteConnection($"Data Source={database}"))
            {
                connection.Open();
                using var create = connection.CreateCommand();
                create.CommandText = """
                    CREATE TABLE session_v2 (
                        id TEXT PRIMARY KEY,
                        slug TEXT,
                        title TEXT,
                        directory TEXT,
                        time_updated INTEGER NOT NULL,
                        time_archived INTEGER
                    );
                    """;
                create.ExecuteNonQuery();

                using var insert = connection.CreateCommand();
                insert.CommandText = """
                    INSERT INTO session_v2(id, slug, title, directory, time_updated, time_archived)
                    VALUES ('ses_current_secret', 'current', 'Live work', 'C:/work/live', $now, NULL),
                           ('ses_old_secret', 'old', 'Old work', 'C:/work/old', $old, NULL);
                    """;
                insert.Parameters.AddWithValue("$now", now);
                insert.Parameters.AddWithValue("$old", now - (long)TimeSpan.FromDays(2).TotalMilliseconds);
                insert.ExecuteNonQuery();
            }

            var reader = new AgentSessionReader(
                root,
                Path.Combine(root, ".claude"),
                Path.Combine(root, ".codex"),
                database);
            var rows = reader.Read();

            var live = Assert.Single(rows, row => row.Title == "Live work");
            Assert.Equal("opencode", live.Framework);
            Assert.Equal("C:/work/live", live.Workspace);
            Assert.True(live.HostLive);
            Assert.Equal(24, live.SessionKey.Length);
            Assert.DoesNotContain("ses_current_secret", live.SessionKey, StringComparison.Ordinal);

            var old = Assert.Single(rows, row => row.Title == "Old work");
            Assert.False(old.HostLive);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), $"axiom-sessions-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        return root;
    }
}
