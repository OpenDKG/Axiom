// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.NetworkRecovery;
using Axiom.Infrastructure.Linux.Dns;

namespace Axiom.Infrastructure.Linux.Tests;

public sealed class DnsBackendTests
{
    private const string ResolvectlDns = "Global:\nLink 2 (eno2): 192.168.70.1 fe80::1%eno2\nLink 3 (wlo1):\nLink 5 (docker0):\n";

    private const string ResolvectlDomain = "Global:\nLink 2 (eno2): lan\nLink 3 (wlo1):\n";

    [Theory]
    [InlineData("../run/systemd/resolve/stub-resolv.conf", true, true, LinuxDnsBackend.SystemdResolved)]
    [InlineData("../run/systemd/resolve/stub-resolv.conf", false, true, LinuxDnsBackend.NetworkManager)]
    [InlineData(null, true, true, LinuxDnsBackend.NetworkManager)]
    [InlineData(null, false, false, LinuxDnsBackend.ResolvConf)]
    public void BackendDetectionPrefersResolvedThenNetworkManager(string? target, bool resolvectl, bool nm, LinuxDnsBackend expected)
    {
        Assert.Equal(expected, LinuxDnsBackendDetector.Decide(target, resolvectl, nm));
    }

    [Fact]
    public void ResolvedBackendListsLinksWithServersAndRedirectsWithRoutingDomain()
    {
        var runner = new FakeRunner().On("resolvectl dns", ResolvectlDns).On("resolvectl domain", ResolvectlDomain);
        var backend = new ResolvedDnsBackend(runner);

        var links = backend.ListLinks();
        var link = Assert.Single(links);
        Assert.Equal("eno2", link.Name);
        Assert.Equal(["192.168.70.1", "fe80::1%eno2"], link.Servers);
        Assert.Equal(["lan"], link.Domains);

        Assert.True(backend.SetDns("eno2", ["127.0.0.1"], ["~."]));
        Assert.Contains("resolvectl dns eno2 127.0.0.1", runner.Calls);
        Assert.Contains("resolvectl domain eno2 ~.", runner.Calls);
        Assert.True(backend.SetDns("eno2", [], []));
        Assert.Contains("resolvectl revert eno2", runner.Calls);
    }

    [Fact]
    public void NetworkManagerBackendReadsActiveConnectionsAndWritesDns()
    {
        var runner = new FakeRunner()
            .On("nmcli -t -f NAME,UUID,DEVICE,TYPE connection show --active", "netplan-eno2:80ab1970:eno2:802-3-ethernet\nlo:312c:lo:loopback\ndocker0:80b7:docker0:bridge\n")
            .On("nmcli -t -g ipv4.dns,ipv4.ignore-auto-dns,ipv6.dns,ipv6.ignore-auto-dns connection show 80ab1970", "1.1.1.1,9.9.9.9\nyes\n\nno\n")
            .On("nmcli -t -g GENERAL.DEVICES connection show 80ab1970", "eno2\n");
        var backend = new NetworkManagerDnsBackend(runner);

        var link = Assert.Single(backend.ListLinks());
        Assert.Equal("80ab1970", link.Name);
        Assert.Equal(["1.1.1.1", "9.9.9.9"], link.Servers);

        Assert.True(backend.SetDns("80ab1970", ["127.0.0.1"], []));
        Assert.Contains("nmcli connection modify 80ab1970 ipv4.dns 127.0.0.1 ipv4.ignore-auto-dns yes ipv6.dns  ipv6.ignore-auto-dns yes", runner.Calls);
        Assert.Contains("nmcli device reapply eno2", runner.Calls);
        Assert.True(backend.SetDns("80ab1970", [], []));
        Assert.Contains("nmcli connection modify 80ab1970 ipv4.dns  ipv4.ignore-auto-dns no ipv6.dns  ipv6.ignore-auto-dns no", runner.Calls);
    }

    [Fact]
    public void ResolvConfRedirectAndRestoreRoundTripTheFile()
    {
        using var temp = new TempDirectory();
        var path = Path.Combine(temp.Path, "resolv.conf");
        File.WriteAllText(path, "# generated\nnameserver 192.168.1.1\nnameserver 8.8.8.8\nsearch home.lan\n");
        var backend = new ResolvConfDnsBackend(path);
        var configurator = new LinuxDnsConfigurator(backend, Path.Combine(temp.Path, "backup.json"));

        var upstreams = configurator.DiscoverUpstreams();
        Assert.Equal(["192.168.1.1", "8.8.8.8"], upstreams.Select(endpoint => endpoint.Address.ToString()));

        var result = configurator.Redirect();
        Assert.True(result.Changed);
        Assert.Equal(["resolv.conf"], result.Links);
        Assert.Contains("nameserver 127.0.0.1", File.ReadAllText(path), StringComparison.Ordinal);
        Assert.True(File.Exists(configurator.BackupPath));
        var backup = configurator.ReadBackup();
        Assert.NotNull(backup);
        Assert.Equal(LinuxDnsBackend.ResolvConf, backup.Backend);
        Assert.Equal(["192.168.1.1", "8.8.8.8"], backup.Links.Single().Servers);
        Assert.Equal(["192.168.1.1", "8.8.8.8"], backup.Upstreams);

        // Already redirected: upstreams come from the backup.
        Assert.Equal(["192.168.1.1", "8.8.8.8"], configurator.DiscoverUpstreams().Select(endpoint => endpoint.Address.ToString()));

        Assert.True(configurator.RestoreIfNeeded());
        Assert.Equal("# generated\nnameserver 192.168.1.1\nnameserver 8.8.8.8\nsearch home.lan\n", File.ReadAllText(path));
        Assert.False(File.Exists(configurator.BackupPath));
        Assert.False(configurator.RestoreIfNeeded());
    }

    [Fact]
    public void ResolvedConfiguratorRestoresSavedServersAndDomains()
    {
        using var temp = new TempDirectory();
        var dnsOutput = ResolvectlDns;
        // FakeRunner answers newest-first: the generic read goes in first so the specific writes shadow it.
        var runner = new FakeRunner();
        runner.On("resolvectl dns", _ => new Axiom.Infrastructure.Unix.Interop.ProcessResult(0, dnsOutput, string.Empty));
        runner.On("resolvectl domain", ResolvectlDomain);
        runner.On("resolvectl dns eno2 127.0.0.1", _ => { dnsOutput = "Global:\nLink 2 (eno2): 127.0.0.1\n"; return new Axiom.Infrastructure.Unix.Interop.ProcessResult(0, string.Empty, string.Empty); });
        var configurator = new LinuxDnsConfigurator(new ResolvedDnsBackend(runner), Path.Combine(temp.Path, "backup.json"));

        Assert.True(configurator.Redirect().Changed);
        Assert.Contains("resolvectl domain eno2 ~.", runner.Calls);
        Assert.Contains("resolvectl flush-caches", runner.Calls);

        runner.On("resolvectl dns eno2 192.168.70.1 fe80::1%eno2", _ => { dnsOutput = ResolvectlDns; return new Axiom.Infrastructure.Unix.Interop.ProcessResult(0, string.Empty, string.Empty); });
        Assert.True(configurator.RestoreIfNeeded());
        Assert.Contains("resolvectl dns eno2 192.168.70.1 fe80::1%eno2", runner.Calls);
        Assert.Contains("resolvectl domain eno2 lan", runner.Calls);
        Assert.False(File.Exists(configurator.BackupPath));
    }

    [Fact]
    public void RecoveryAdapterMapsLinksToAdapterStatesAndValidatesApply()
    {
        var runner = new FakeRunner().On("resolvectl dns", ResolvectlDns).On("resolvectl domain", ResolvectlDomain);
        var adapter = new LinuxDnsRecoveryAdapter(new ResolvedDnsBackend(runner));

        var state = Assert.Single(adapter.CaptureDns());
        Assert.Equal("eno2", state.InterfaceAlias);
        Assert.Equal(LinuxDnsRecoveryAdapter.LinkId(LinuxDnsBackend.SystemdResolved, "eno2"), state.AdapterId);
        Assert.Equal(NetworkDnsMode.Static, state.Ipv4Mode);
        Assert.Equal(["192.168.70.1"], state.Ipv4Servers);
        Assert.Equal(["fe80::1"], state.Ipv6Servers);
        Assert.False(adapter.AnyAdapterUsesLoopbackDns());

        // Same servers already in place: no tool call beyond the read.
        adapter.ApplyDns(state);
        Assert.DoesNotContain(runner.Calls, call => call.StartsWith("resolvectl dns eno2 ", StringComparison.Ordinal));

        var wrongId = state with { AdapterId = Guid.NewGuid() };
        var error = Assert.Throws<NetworkRecoveryPlatformException>(() => adapter.ApplyDns(wrongId));
        Assert.Equal("dns_adapter_invalid", error.Code);

        var badServers = state with { Ipv4Servers = ["not-an-ip"] };
        Assert.Equal("dns_state_invalid", Assert.Throws<NetworkRecoveryPlatformException>(() => adapter.ApplyDns(badServers)).Code);
    }
}
