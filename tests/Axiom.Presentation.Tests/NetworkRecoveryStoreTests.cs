// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class NetworkRecoveryStoreTests
{
    private static NetworkRecoverySnapshot Snapshot() => new(
        new DateTimeOffset(2026, 11, 11, 20, 0, 0, TimeSpan.Zero),
        [
            new NetworkAdapterDns("adapter-1", "Ethernet", UsesDhcp: false, ["192.168.0.1", "1.1.1.1"]),
            new NetworkAdapterDns("adapter-2", "Wi-Fi", UsesDhcp: true, []),
        ],
        ["{11111111-1111-1111-1111-111111111111}", "{22222222-2222-2222-2222-222222222222}"],
        ProtectionWasActive: true);

    [Fact]
    public void Snapshot_round_trips_through_text()
    {
        var restored = NetworkRecoveryStore.Parse(NetworkRecoveryStore.Serialize(Snapshot()));

        Assert.Equal(NetworkRecoveryStore.Serialize(Snapshot()), NetworkRecoveryStore.Serialize(restored));
    }

    [Fact]
    public void File_round_trip_uses_the_documented_format()
    {
        var directory = Path.Combine(Path.GetTempPath(), "axiom-net-recovery", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "network-recovery.txt");

        try
        {
            NetworkRecoveryStore.SaveTo(path, Snapshot());
            var text = File.ReadAllText(path);

            Assert.StartsWith("axiom-network-recovery=1", text, StringComparison.Ordinal);
            Assert.Contains("adapter|adapter-1|Ethernet|0|192.168.0.1;1.1.1.1", text, StringComparison.Ordinal);
            var restored = NetworkRecoveryStore.LoadFrom(path);
            Assert.Equal(NetworkRecoveryStore.Serialize(Snapshot()), NetworkRecoveryStore.Serialize(restored));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Unknown_or_malformed_text_is_empty_not_guessed()
    {
        Assert.True(NetworkRecoveryStore.Parse("garbage").IsEmpty);
        Assert.True(NetworkRecoveryStore.Parse("axiom-network-recovery=1\nadapter|broken").IsEmpty);
        Assert.True(NetworkRecoveryStore.LoadFrom(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"))).IsEmpty);
    }

    [Fact]
    public void Separator_characters_cannot_break_the_format()
    {
        var snapshot = Snapshot() with
        {
            Adapters = [new NetworkAdapterDns("a|b", "line\nbreak", UsesDhcp: false, ["1.1.1.1|2.2.2.2"])],
        };

        var restored = NetworkRecoveryStore.Parse(NetworkRecoveryStore.Serialize(snapshot));

        var adapter = Assert.Single(restored.Adapters);
        Assert.Equal("a/b", adapter.AdapterId);
        Assert.Equal("line break", adapter.Description);
        Assert.Equal(["1.1.1.1/2.2.2.2"], adapter.Servers);
    }
}
