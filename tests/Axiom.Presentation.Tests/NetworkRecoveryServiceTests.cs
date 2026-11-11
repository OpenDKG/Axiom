// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class NetworkRecoveryServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 11, 20, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Restore_reapplies_each_adapter_and_removes_only_captured_rules()
    {
        var platform = new FakePlatform
        {
            Adapters = [Adapter("a1", "Ethernet"), Adapter("a2", "Wi-Fi")],
            Rules = ["Axiom::r1::OUT", "Axiom::r2::IN"],
        };
        var service = new NetworkRecoveryService(platform, () => Now);
        var snapshot = service.Capture(protectionActive: true);

        platform.Applied.Clear();
        platform.Removed.Clear();
        var result = service.Restore(snapshot);

        Assert.True(result.Succeeded);
        Assert.Equal(2, result.AdaptersRestored);
        Assert.Equal(2, result.RulesRemoved);
        Assert.Equal(["Ethernet", "Wi-Fi"], platform.Applied);
        Assert.Equal(["Axiom::r1::OUT", "Axiom::r2::IN"], platform.Removed);
        Assert.Equal(Now, snapshot.CapturedUtc);
        Assert.True(snapshot.ProtectionWasActive);
    }

    [Fact]
    public void Restore_reports_partial_failures_and_continues()
    {
        var platform = new FakePlatform
        {
            Adapters = [Adapter("a1", "Ethernet"), Adapter("a2", "Wi-Fi")],
            Rules = ["Axiom::r1::OUT"],
            FailAdapter = "Ethernet",
            FailRule = "Axiom::r1::OUT",
        };
        var snapshot = new NetworkRecoverySnapshot(Now, platform.Adapters, platform.Rules, true);

        var result = new NetworkRecoveryService(platform).Restore(snapshot);

        Assert.False(result.Succeeded);
        Assert.Equal(2, result.Problems.Count);
        Assert.Equal(1, result.AdaptersRestored);
        Assert.Equal(0, result.RulesRemoved);
        Assert.Contains("Wi-Fi", platform.Applied);
    }

    [Fact]
    public void Restore_without_saved_state_is_an_error_not_a_silent_success()
    {
        var result = new NetworkRecoveryService(new FakePlatform())
            .Restore(NetworkRecoverySnapshot.Empty);

        Assert.False(result.Succeeded);
        Assert.Equal(0, result.RulesRemoved);
        Assert.Contains("No saved network state", result.Problems[0], StringComparison.Ordinal);
    }

    private static NetworkAdapterDns Adapter(string id, string description) =>
        new(id, description, UsesDhcp: false, ["192.168.0.1"]);

    private sealed class FakePlatform : INetworkRecoveryPlatform
    {
        public IReadOnlyList<NetworkAdapterDns> Adapters { get; init; } = [];

        public IReadOnlyList<string> Rules { get; init; } = [];

        public string? FailAdapter { get; init; }

        public string? FailRule { get; init; }

        public List<string> Applied { get; } = [];

        public List<string> Removed { get; } = [];

        public IReadOnlyList<NetworkAdapterDns> CaptureAdapters() => Adapters;

        public IReadOnlyList<string> CaptureAxiomRules() => Rules;

        public void ApplyAdapterDns(NetworkAdapterDns adapter)
        {
            if (adapter.Description == FailAdapter)
            {
                throw new InvalidOperationException("denied");
            }

            Applied.Add(adapter.Description);
        }

        public void RemoveAxiomRule(string displayName)
        {
            if (displayName == FailRule)
            {
                throw new UnauthorizedAccessException("denied");
            }

            Removed.Add(displayName);
        }
    }
}
