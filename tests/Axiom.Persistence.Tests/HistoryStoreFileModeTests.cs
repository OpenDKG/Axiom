// SPDX-License-Identifier: GPL-3.0-or-later
using Xunit;

namespace Axiom.Persistence.Tests;

/// <summary>
/// Gate B (#441): the history database is private to the service account on Unix (0600). Windows
/// keeps the ACL layout; the check returns early there.
/// </summary>
public sealed class HistoryStoreFileModeTests
{
    [Fact]
    public async Task History_database_is_owner_only_on_unix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var directory = Directory.CreateTempSubdirectory("axiom-history-mode-");
        try
        {
            var path = Path.Combine(directory.FullName, "axiom.db");
            var store = new HistoryStore(path);
            await store.InitializeAsync();

            Assert.True(File.Exists(path));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            directory.Delete(recursive: true);
        }
    }
}
