// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.NetworkRecovery;
using Axiom.Infrastructure.MacOS.Dns;
using Axiom.Infrastructure.MacOS.Interop;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class MacDnsRecoveryAdapterTests
{
    [Fact]
    public void ServiceIdIsStableAndDistinctPerServiceName()
    {
        Assert.Equal(MacDnsRecoveryAdapter.ServiceId("Wi-Fi"), MacDnsRecoveryAdapter.ServiceId("Wi-Fi"));
        Assert.NotEqual(MacDnsRecoveryAdapter.ServiceId("Wi-Fi"), MacDnsRecoveryAdapter.ServiceId("Ethernet"));
        Assert.NotEqual(Guid.Empty, MacDnsRecoveryAdapter.ServiceId("Ethernet"));
    }

    [Fact]
    public void ToStateSplitsStaticServersByFamilyAndMarksEmptyAsAutomatic()
    {
        var state = MacDnsRecoveryAdapter.ToState("Ethernet", "en0", ["10.0.2.3", "2001:db8::1", "10.0.2.3", "junk"]);

        Assert.Equal(MacDnsRecoveryAdapter.ServiceId("Ethernet"), state.AdapterId);
        Assert.Equal("Ethernet", state.InterfaceAlias);
        Assert.Equal("en0", state.Description);
        Assert.Equal(NetworkDnsMode.Static, state.Ipv4Mode);
        Assert.Equal(["10.0.2.3"], state.Ipv4Servers);
        Assert.Equal(NetworkDnsMode.Static, state.Ipv6Mode);
        Assert.Equal(["2001:db8::1"], state.Ipv6Servers);

        var automatic = MacDnsRecoveryAdapter.ToState("Wi-Fi", "en1", []);
        Assert.Equal(NetworkDnsMode.Automatic, automatic.Ipv4Mode);
        Assert.Equal(NetworkDnsMode.Automatic, automatic.Ipv6Mode);
        Assert.Empty(MacDnsRecoveryAdapter.ExpectedServers(automatic));
        Assert.Equal(["10.0.2.3", "2001:db8::1"], MacDnsRecoveryAdapter.ExpectedServers(state));
    }

    [Fact]
    public void CaptureReadsEveryEnabledServiceAndSurvivesTheSnapshotStoreRoundTrip()
    {
        using var temp = new TempDirectory();
        var runner = new FakeRunner()
            .On("networksetup -listallnetworkservices", "An asterisk (*) denotes that a network service is disabled.\nEthernet\n*Bluetooth PAN\n")
            .On("networksetup -listnetworkserviceorder", "(1) Ethernet\n(Hardware Port: Ethernet, Device: en0)\n\n")
            .On("networksetup -getdnsservers", arguments => new ProcessResult(
                0,
                arguments[1] == "Ethernet" ? "10.0.2.3\n" : "There aren't any DNS Servers set on Bluetooth PAN.\n",
                string.Empty));
        var adapter = new MacDnsRecoveryAdapter(new MacDnsConfigurator(runner, Path.Combine(temp.Path, "backup.json")));

        var captured = adapter.CaptureDns();

        var state = Assert.Single(captured);
        Assert.Equal("Ethernet", state.InterfaceAlias);
        Assert.Equal(["10.0.2.3"], state.Ipv4Servers);

        var snapshot = new NetworkRecoverySnapshot
        {
            CapturedUtc = DateTimeOffset.UtcNow,
            ProtectionWasActive = false,
            Adapters = captured,
            Rules = [],
        };
        Assert.True(NetworkRecoverySnapshotStore.TryValidate(snapshot, out var validation), validation);
        var path = Path.Combine(temp.Path, NetworkRecoverySnapshotStore.FileName);
        Assert.True(NetworkRecoverySnapshotStore.TryWrite(path, snapshot, out var writeError), writeError);
        Assert.Contains("Ethernet", File.ReadAllText(path), StringComparison.Ordinal);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
        }
    }

    [Fact]
    public void ApplyRejectsAnIdentityThatDoesNotBelongToTheService()
    {
        using var temp = new TempDirectory();
        var runner = new FakeRunner();
        var adapter = new MacDnsRecoveryAdapter(new MacDnsConfigurator(runner, Path.Combine(temp.Path, "backup.json")));
        var forged = MacDnsRecoveryAdapter.ToState("Ethernet", "en0", ["10.0.2.3"]) with { AdapterId = Guid.NewGuid() };

        var failure = Assert.Throws<NetworkRecoveryPlatformException>(() => adapter.ApplyDns(forged));

        Assert.Contains("does not belong to network service", failure.Message, StringComparison.Ordinal);
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public void ApplyWritesTheSavedServersBackAndVerifies()
    {
        using var temp = new TempDirectory();
        var dns = "127.0.0.1";
        var runner = new FakeRunner()
            .On("networksetup -getdnsservers", _ => new ProcessResult(0, dns + "\n", string.Empty))
            .On("networksetup -setdnsservers", arguments =>
            {
                dns = string.Join(' ', arguments.Skip(2));
                return new ProcessResult(0, string.Empty, string.Empty);
            })
            .On("dscacheutil -flushcache", string.Empty);
        var adapter = new MacDnsRecoveryAdapter(new MacDnsConfigurator(runner, Path.Combine(temp.Path, "backup.json")));

        adapter.ApplyDns(MacDnsRecoveryAdapter.ToState("Ethernet", "en0", ["10.0.2.3"]));

        Assert.Equal("10.0.2.3", dns);
    }
}
