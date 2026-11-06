// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Microsoft.Data.Sqlite;
using Netpetra.Persistence;
using Xunit;

namespace Netpetra.Persistence.Tests;

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

    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), $"netpetra-sessions-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        return root;
    }
}
