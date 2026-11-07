// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Globalization;
using System.IO;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class BlackboxAutoSyncStoreTests
{
    [Fact]
    public void Auto_sync_state_round_trips()
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            "axiom-auto-sync-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "auto-sync.json");
        try
        {
            var store = new BlackboxAutoSyncStore(path);
            var value = new BlackboxAutoSyncSettings(
                true,
                DateTimeOffset.Parse("2026-11-07T03:00:00Z", CultureInfo.InvariantCulture),
                "Auto-sync requested.");

            store.Save(value);
            var loaded = store.Load();

            Assert.True(loaded.Enabled);
            Assert.Equal(value.LastAttemptUtc, loaded.LastAttemptUtc);
            Assert.Equal(value.LastStatus, loaded.LastStatus);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
