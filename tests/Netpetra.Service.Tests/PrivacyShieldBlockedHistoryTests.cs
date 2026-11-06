// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Netpetra.Contracts.Privacy;
using Xunit;

namespace Netpetra.Service.Tests;

public sealed class PrivacyShieldBlockedHistoryTests
{
    [Fact]
    public void History_is_bounded_newest_first_and_clearable()
    {
        var path = Path.Combine(Path.GetTempPath(), $"netpetra-blocked-{Guid.NewGuid():N}.jsonl");
        try
        {
            var store = new PrivacyShieldBlockedHistoryStore(path);
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
