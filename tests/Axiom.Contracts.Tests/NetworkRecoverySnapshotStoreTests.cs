// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.NetworkRecovery;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class NetworkRecoverySnapshotStoreTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 11, 20, 0, 0, TimeSpan.Zero);

    private static NetworkRecoverySnapshot Snapshot() => new()
    {
        CapturedUtc = Now,
        ProtectionWasActive = true,
        Adapters =
        [
            new NetworkAdapterDnsState
            {
                AdapterId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
                InterfaceAlias = "Ethernet",
                Description = "Intel(R) Ethernet",
                Ipv4Mode = NetworkDnsMode.Static,
                Ipv4Servers = ["192.168.0.1", "1.1.1.1"],
                Ipv6Mode = NetworkDnsMode.Automatic,
            },
            new NetworkAdapterDnsState
            {
                AdapterId = Guid.Parse("22222222-2222-2222-2222-222222222222"),
                InterfaceAlias = "Wi-Fi",
                Description = "Wireless",
                Ipv4Mode = NetworkDnsMode.Automatic,
                Ipv6Mode = NetworkDnsMode.Static,
                Ipv6Servers = ["2606:4700:4700::1111"],
            },
        ],
        Rules =
        [
            new NetworkOwnedRuleState
            {
                ManagedRuleId = Guid.Parse("33333333-3333-3333-3333-333333333333"),
                Direction = FirewallDirection.Outbound,
                OwnershipGroup = "Axiom",
            },
        ],
    };

    [Fact]
    public void Snapshot_round_trips_with_modes_servers_and_rules()
    {
        var text = NetworkRecoverySnapshotStore.Serialize(Snapshot());
        var read = NetworkRecoverySnapshotStore.Parse(text);

        Assert.Equal(NetworkRecoverySnapshotReadStatus.Valid, read.Status);
        Assert.NotNull(read.Snapshot);
        Assert.Equal(text, NetworkRecoverySnapshotStore.Serialize(read.Snapshot));
        Assert.Equal(NetworkDnsMode.Static, read.Snapshot.Adapters[0].Ipv4Mode);
        Assert.Equal(NetworkDnsMode.Automatic, read.Snapshot.Adapters[0].Ipv6Mode);
        Assert.Equal(["192.168.0.1", "1.1.1.1"], read.Snapshot.Adapters[0].Ipv4Servers);
        Assert.Equal(["2606:4700:4700::1111"], read.Snapshot.Adapters[1].Ipv6Servers);
    }

    [Fact]
    public void Valid_empty_snapshot_is_a_valid_capture_not_a_missing_one()
    {
        var snapshot = new NetworkRecoverySnapshot
        {
            CapturedUtc = Now,
            ProtectionWasActive = false,
        };

        var read = NetworkRecoverySnapshotStore.Parse(NetworkRecoverySnapshotStore.Serialize(snapshot));

        Assert.Equal(NetworkRecoverySnapshotReadStatus.Valid, read.Status);
        Assert.Empty(read.Snapshot!.Adapters);
        Assert.Empty(read.Snapshot.Rules);
    }

    [Fact]
    public void Edited_or_truncated_text_is_rejected_by_the_checksum()
    {
        var text = NetworkRecoverySnapshotStore.Serialize(Snapshot());

        var edited = text.Replace("1.1.1.1", "9.9.9.9", StringComparison.Ordinal);
        var truncated = text[..^20];

        Assert.Equal(NetworkRecoverySnapshotReadStatus.Corrupt, NetworkRecoverySnapshotStore.Parse(edited).Status);
        Assert.Equal(NetworkRecoverySnapshotReadStatus.Corrupt, NetworkRecoverySnapshotStore.Parse(truncated).Status);
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("axiom-network-recovery=1\ncaptured=2026-11-11T20:00:00+00:00\nprotection=active\nchecksum=00\n")]
    [InlineData("axiom-network-recovery=2\ncaptured=2026-11-11T20:00:00+00:00\nprotection=active\n\nchecksum=00\n")]
    [InlineData("axiom-network-recovery=2\ncaptured=not-a-date\nprotection=active\nchecksum=00\n")]
    public void Malformed_text_is_corrupt_not_guessed(string text)
    {
        Assert.Equal(NetworkRecoverySnapshotReadStatus.Corrupt, NetworkRecoverySnapshotStore.Parse(text).Status);
    }

    [Fact]
    public void Unknown_entries_are_rejected_even_with_a_valid_checksum()
    {
        var text = NetworkRecoverySnapshotStore.Serialize(Snapshot());
        var lines = text.TrimEnd('\n').Split('\n').ToList();
        lines.Insert(lines.Count - 1, "unknown|value");
        var body = string.Join('\n', lines.Take(lines.Count - 1)) + "\n";
        var checksum = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(body)))
            .ToLowerInvariant();
        var forged = body + "checksum=" + checksum + "\n";

        Assert.Equal(NetworkRecoverySnapshotReadStatus.Corrupt, NetworkRecoverySnapshotStore.Parse(forged).Status);
    }

    [Theory]
    [InlineData(NetworkDnsMode.Automatic, new[] { "1.1.1.1" })]
    [InlineData(NetworkDnsMode.Static, new string[0])]
    public void Automatic_and_static_server_lists_must_match_their_mode(
        NetworkDnsMode mode,
        string[] servers)
    {
        var snapshot = Snapshot() with
        {
            Adapters =
            [
                new NetworkAdapterDnsState
                {
                    AdapterId = Guid.NewGuid(),
                    InterfaceAlias = "Ethernet",
                    Description = "Test",
                    Ipv4Mode = mode,
                    Ipv4Servers = servers,
                    Ipv6Mode = NetworkDnsMode.Automatic,
                },
            ],
            Rules = [],
        };

        Assert.False(NetworkRecoverySnapshotStore.TryValidate(snapshot, out var error));
        Assert.NotNull(error);
    }

    [Fact]
    public void A_server_of_the_wrong_address_family_is_invalid()
    {
        var snapshot = Snapshot() with
        {
            Adapters =
            [
                new NetworkAdapterDnsState
                {
                    AdapterId = Guid.NewGuid(),
                    InterfaceAlias = "Ethernet",
                    Description = "Test",
                    Ipv4Mode = NetworkDnsMode.Static,
                    Ipv4Servers = ["2606:4700:4700::1111"],
                    Ipv6Mode = NetworkDnsMode.Automatic,
                },
            ],
            Rules = [],
        };

        Assert.False(NetworkRecoverySnapshotStore.TryValidate(snapshot, out _));
    }

    [Fact]
    public void Duplicate_identities_are_rejected()
    {
        var adapter = Snapshot().Adapters[0];
        var rule = Snapshot().Rules[0];

        Assert.False(NetworkRecoverySnapshotStore.TryValidate(
            Snapshot() with { Adapters = [adapter, adapter] },
            out _));
        Assert.False(NetworkRecoverySnapshotStore.TryValidate(
            Snapshot() with { Rules = [rule, rule] },
            out _));
    }

    [Fact]
    public void File_round_trip_uses_the_documented_format_and_missing_is_distinct()
    {
        var directory = Path.Combine(Path.GetTempPath(), "axiom-net-recovery", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, NetworkRecoverySnapshotStore.FileName);

        try
        {
            Assert.Equal(NetworkRecoverySnapshotReadStatus.Missing, NetworkRecoverySnapshotStore.Read(path).Status);

            Assert.True(NetworkRecoverySnapshotStore.TryWrite(path, Snapshot(), out var error), error);
            var text = File.ReadAllText(path);

            Assert.StartsWith("axiom-network-recovery=2", text, StringComparison.Ordinal);
            Assert.Contains("adapter|11111111-1111-1111-1111-111111111111|Ethernet|Intel(R) Ethernet|static|", text, StringComparison.Ordinal);
            Assert.Contains("rule|33333333-3333-3333-3333-333333333333|OUT|Axiom", text, StringComparison.Ordinal);
            var lastLine = text.TrimEnd('\n').Split('\n')[^1];
            Assert.StartsWith("checksum=", lastLine, StringComparison.Ordinal);
            Assert.Equal(64, lastLine.Length - "checksum=".Length);

            var read = NetworkRecoverySnapshotStore.Read(path);
            Assert.Equal(NetworkRecoverySnapshotReadStatus.Valid, read.Status);
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public void An_invalid_snapshot_is_never_written_over_an_existing_file()
    {
        var directory = Path.Combine(Path.GetTempPath(), "axiom-net-recovery", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, NetworkRecoverySnapshotStore.FileName);

        try
        {
            Assert.True(NetworkRecoverySnapshotStore.TryWrite(path, Snapshot(), out _));
            var before = File.ReadAllText(path);

            var invalid = Snapshot() with { CapturedUtc = default };
            Assert.False(NetworkRecoverySnapshotStore.TryWrite(path, invalid, out _));
            Assert.Equal(before, File.ReadAllText(path));
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public void Separator_and_control_characters_cannot_break_the_format()
    {
        var snapshot = Snapshot() with
        {
            Adapters =
            [
                new NetworkAdapterDnsState
                {
                    AdapterId = Guid.NewGuid(),
                    InterfaceAlias = "a|b\r\nc",
                    Description = "line\nbreak",
                    Ipv4Mode = NetworkDnsMode.Static,
                    Ipv4Servers = ["1.1.1.1"],
                    Ipv6Mode = NetworkDnsMode.Automatic,
                },
            ],
            Rules = [],
        };

        var read = NetworkRecoverySnapshotStore.Parse(NetworkRecoverySnapshotStore.Serialize(snapshot));

        Assert.Equal(NetworkRecoverySnapshotReadStatus.Valid, read.Status);
        var adapter = Assert.Single(read.Snapshot!.Adapters);
        Assert.Equal("a/b  c", adapter.InterfaceAlias);
        Assert.Equal("line break", adapter.Description);
    }
}
