// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Service;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class NetworkRecoveryCommandTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "axiom-recovery-command-tests",
        Guid.NewGuid().ToString("N"));

    private readonly string _path;

    public NetworkRecoveryCommandTests()
    {
        _path = Path.Combine(_directory, NetworkRecoverySnapshotStore.FileName);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public void Missing_snapshot_is_reported_without_a_plan_or_a_change()
    {
        var exit = NetworkRecoveryCommand.Run(["--recover-network"], _path);

        Assert.Equal(NetworkRecoveryCommand.ExitCodes.NoSnapshot, exit);
        Assert.False(File.Exists(_path));
    }

    [Fact]
    public void Corrupt_snapshot_is_refused()
    {
        Directory.CreateDirectory(_directory);
        File.WriteAllText(_path, "axiom-network-recovery=2\nbroken");

        var exit = NetworkRecoveryCommand.Run(["--recover-network"], _path);

        Assert.Equal(NetworkRecoveryCommand.ExitCodes.SnapshotRefused, exit);
    }

    [Fact]
    public void Valid_snapshot_is_a_dry_run_unless_apply_is_explicit()
    {
        Assert.True(NetworkRecoverySnapshotStore.TryWrite(_path, Snapshot(), out var error), error);

        var exit = NetworkRecoveryCommand.Run(["--recover-network"], _path);

        Assert.Equal(NetworkRecoveryCommand.ExitCodes.PlanOnly, exit);
        Assert.Equal(
            NetworkRecoverySnapshotReadStatus.Valid,
            NetworkRecoverySnapshotStore.Read(_path).Status);
    }

    private static NetworkRecoverySnapshot Snapshot() => new()
    {
        CapturedUtc = DateTimeOffset.UtcNow,
        ProtectionWasActive = true,
        Adapters =
        [
            new NetworkAdapterDnsState
            {
                AdapterId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
                InterfaceAlias = "Ethernet",
                Description = "Test",
                Ipv4Mode = NetworkDnsMode.Static,
                Ipv4Servers = ["192.168.0.1"],
                Ipv6Mode = NetworkDnsMode.Automatic,
            },
        ],
        Rules =
        [
            new NetworkOwnedRuleState
            {
                ManagedRuleId = Guid.Parse("22222222-2222-2222-2222-222222222222"),
                Direction = FirewallDirection.Outbound,
                OwnershipGroup = "Axiom",
            },
        ],
    };
}
