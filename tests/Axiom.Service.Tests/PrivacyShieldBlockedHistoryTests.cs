// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.Contracts.Privacy;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class PrivacyShieldBlockedHistoryTests
{
    [Fact]
    public void History_keeps_only_recent_entries_while_a_write_fails()
    {
        var root = Path.Combine(Path.GetTempPath(), $"axiom-blocked-{Guid.NewGuid():N}");
        var path = Path.Combine(root, "history.jsonl");
        File.WriteAllText(root, "The history directory is temporarily inaccessible.");
        try
        {
            using var store = new PrivacyShieldBlockedHistoryStore(path);
            var limit = PrivacyShieldBlockedHistoryStore.MaxEntries;
            for (var index = 0; index < limit + 10; index++)
            {
                store.Append(new PrivacyShieldBlockedEvent(
                    $"name-{index}.example", PrivacyCategory.Ads, DateTimeOffset.UnixEpoch.AddSeconds(index)));
            }

            File.Delete(root);
            Directory.CreateDirectory(root);
            store.Flush();

            Assert.Equal(limit, File.ReadLines(path).Count());
            Assert.Equal("name-10.example", store.LoadRecent()[^1].Domain);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                File.Delete(path);
                Directory.Delete(root);
            }
            else
            {
                File.Delete(root);
            }
        }
    }

    [Fact]
    public void History_is_bounded_newest_first_and_clearable()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-blocked-{Guid.NewGuid():N}.jsonl");
        try
        {
            using var store = new PrivacyShieldBlockedHistoryStore(path);
            var first = new PrivacyShieldBlockedEvent(
                "first.example",
                PrivacyCategory.Ads,
                DateTimeOffset.UtcNow.AddSeconds(-1));
            var second = new PrivacyShieldBlockedEvent(
                "second.example",
                PrivacyCategory.Tracking,
                DateTimeOffset.UtcNow);

            store.Append(first);
            store.Append(second);

            var loaded = store.LoadRecent();
            Assert.Equal(2, loaded.Count);
            Assert.Equal("second.example", loaded[0].Domain);
            Assert.Equal("first.example", loaded[1].Domain);
            store.Flush();
            Assert.True(File.Exists(path));
            Assert.DoesNotContain("allowed.example", File.ReadAllText(path), StringComparison.Ordinal);

            store.Clear();
            Assert.Empty(store.LoadRecent());
            Assert.False(File.Exists(path));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
