// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.Persistence;
using Xunit;

namespace Netpetra.Persistence.Tests;

public sealed class LocalDatabaseTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "netpetra-tests",
        Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public async Task Initialize_creates_a_healthy_wal_database()
    {
        var path = Path.Combine(_directory, "netpetra.db");
        var database = new LocalDatabase(path);

        var health = await database.InitializeAsync(CancellationToken.None);

        Assert.True(health.IsHealthy);
        Assert.Equal("wal", health.JournalMode, ignoreCase: true);
        Assert.True(health.ForeignKeysEnabled);
        Assert.Equal(LocalDatabase.BaselineSchemaVersion, health.SchemaVersion);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task Initialize_is_idempotent()
    {
        var path = Path.Combine(_directory, "netpetra.db");
        var database = new LocalDatabase(path);

        var first = await database.InitializeAsync(CancellationToken.None);
        var second = await database.InitializeAsync(CancellationToken.None);

        Assert.True(first.IsHealthy);
        Assert.True(second.IsHealthy);
        Assert.Equal(first.SchemaVersion, second.SchemaVersion);
    }

    [Fact]
    public void Relative_path_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => new LocalDatabase("netpetra.db"));
    }

    [Fact]
    public async Task Cancellation_is_observed_before_opening()
    {
        var database = new LocalDatabase(Path.Combine(_directory, "netpetra.db"));
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            database.InitializeAsync(cancellation.Token));
    }
}
