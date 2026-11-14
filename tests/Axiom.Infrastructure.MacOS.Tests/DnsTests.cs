// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Contracts.Privacy;
using Axiom.Infrastructure.MacOS.Dns;
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Service.Hosting.Dns;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class DnsTests
{
    private static readonly string[] ExpectedScutilServers = ["192.168.64.1", "2001:db8::53", "127.0.0.1", "8.8.8.8"];

    private const string Services = """
        An asterisk (*) denotes that a network service is disabled.
        Ethernet
        *Bluetooth PAN
        Thunderbolt Bridge
        Wi-Fi

        """;

    private const string Scutil = """
        DNS configuration

        resolver #1
          search domain[0] : lan
          nameserver[0] : 192.168.64.1
          nameserver[1] : 2001:db8::53
          if_index : 4 (en0)
          flags    : Request A records, Request AAAA records
          reach    : 0x00020002 (Reachable,Directly Reachable Address)

        resolver #2
          domain   : local
          options  : mdns
          timeout  : 5

        resolver #3
          nameserver[0] : 127.0.0.1

        DNS configuration (for scoped queries)

        resolver #1
          nameserver[0] : 192.168.64.1
          nameserver[1] : 8.8.8.8
          if_index : 4 (en0)
        """;

    [Fact]
    public void ParsesNetworkServices()
    {
        var services = NetworkSetupParser.ParseServices(Services);

        Assert.Equal(["Ethernet", "Bluetooth PAN", "Thunderbolt Bridge", "Wi-Fi"], services.Select(service => service.Name));
        Assert.False(services[1].Enabled);
        Assert.True(services[0].Enabled);
    }

    [Fact]
    public void ParsesDnsServers()
    {
        Assert.Equal(["1.1.1.1", "2606:4700:4700::1111"], NetworkSetupParser.ParseDnsServers("1.1.1.1\n2606:4700:4700::1111\n"));
        Assert.Empty(NetworkSetupParser.ParseDnsServers("There aren't any DNS Servers set on Ethernet.\n")!);
        Assert.Null(NetworkSetupParser.ParseDnsServers("Ethernet2 is not a recognized network service.\n** Error: The parameters were not valid."));
    }

    [Fact]
    public void ParsesScutilDefaultResolvers()
    {
        var servers = NetworkSetupParser.ParseScutilNameservers(Scutil);

        Assert.Equal(
            ExpectedScutilServers,
            servers.Select(server => server.ToString()));
    }

    [Fact]
    public void ParsesServiceOrderAndInterfaceStatus()
    {
        const string order = """
            An asterisk (*) denotes that a network service is disabled.
            (1) Ethernet
            (Hardware Port: Ethernet, Device: en0)

            (2) Thunderbolt Bridge
            (Hardware Port: Thunderbolt Bridge, Device: bridge0)

            (*) Bluetooth PAN
            (Hardware Port: Bluetooth PAN, Device: en5)

            """;

        Assert.Equal(
            [("Ethernet", "en0"), ("Thunderbolt Bridge", "bridge0"), ("Bluetooth PAN", "en5")],
            NetworkSetupParser.ParseServiceOrder(order).Select(entry => (entry.Name, entry.Device)));
        Assert.True(NetworkSetupParser.ParseInterfaceActive("en0: flags=8863<UP,BROADCAST> mtu 1500\n\tinet 10.0.2.15\n\tstatus: active\n"));
        Assert.False(NetworkSetupParser.ParseInterfaceActive("bridge0: flags=8863<UP> mtu 1500\n\tstatus: inactive\n"));
        Assert.Null(NetworkSetupParser.ParseInterfaceActive("lo0: flags=8049<UP,LOOPBACK> mtu 16384\n"));
    }

    [Fact]
    public void RedirectSkipsServicesWithAnInactiveInterfaceButRestoreCoversAll()
    {
        using var temp = new TempDirectory();
        var dns = new Dictionary<string, string> { ["Ethernet"] = "10.0.2.3", ["Thunderbolt Bridge"] = "", ["Wi-Fi"] = "" };
        var runner = new FakeRunner()
            .On("networksetup -listallnetworkservices", "An asterisk (*) denotes that a network service is disabled.\nEthernet\nThunderbolt Bridge\nWi-Fi\n")
            .On("networksetup -listnetworkserviceorder", "(1) Ethernet\n(Hardware Port: Ethernet, Device: en0)\n\n(2) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n")
            .On("ifconfig en0", "en0: flags=8863<UP> mtu 1500\n\tstatus: active\n")
            .On("ifconfig bridge0", "bridge0: flags=8863<UP> mtu 1500\n\tstatus: inactive\n")
            .On("scutil --dns", "resolver #1\n  nameserver[0] : 10.0.2.3\n")
            .On("networksetup -getdnsservers", arguments => new ProcessResult(0, dns[arguments[1]].Length == 0 ? $"There aren't any DNS Servers set on {arguments[1]}.\n" : dns[arguments[1]] + "\n", string.Empty))
            .On("networksetup -setdnsservers", arguments =>
            {
                dns[arguments[1]] = arguments[2] == "Empty" ? string.Empty : string.Join(' ', arguments.Skip(2));
                return new ProcessResult(0, string.Empty, string.Empty);
            });
        var configurator = new MacDnsConfigurator(runner, Path.Combine(temp.Path, "backup.json"));

        var result = configurator.Redirect();

        // Ethernet (active) and Wi-Fi (no device known: conservative) are redirected; the inactive bridge is not.
        Assert.Equal(["Ethernet", "Wi-Fi"], result.Services);
        Assert.Equal("127.0.0.1", dns["Ethernet"]);
        Assert.Equal("127.0.0.1", dns["Wi-Fi"]);
        Assert.Equal("", dns["Thunderbolt Bridge"]);
        Assert.Equal(["Ethernet", "Wi-Fi"], configurator.ReadBackup()!.Services.Select(service => service.Name));

        // Restore walks every enabled service, including one redirected by hand meanwhile.
        dns["Thunderbolt Bridge"] = "127.0.0.1";
        Assert.True(configurator.RestoreIfNeeded());
        Assert.Equal("10.0.2.3", dns["Ethernet"]);
        Assert.Equal("", dns["Wi-Fi"]);
        Assert.Equal("", dns["Thunderbolt Bridge"]);
    }

    [Fact]
    public void RedirectSavesBackupAndRestoreRevertsIt()
    {
        using var temp = new TempDirectory();
        var dns = new Dictionary<string, string[]>
        {
            ["Ethernet"] = [],
            ["Wi-Fi"] = ["9.9.9.9"],
            ["Bluetooth PAN"] = ["1.0.0.1"],
        };
        var runner = new FakeRunner()
            .On("networksetup -listallnetworkservices", Services)
            .On("networksetup -getdnsservers", args =>
                dns.TryGetValue(args[1], out var servers)
                    ? new ProcessResult(0, servers.Length == 0 ? $"There aren't any DNS Servers set on {args[1]}.\n" : string.Join('\n', servers) + "\n", string.Empty)
                    : new ProcessResult(0, $"{args[1]} is not a recognized network service.\n** Error: The parameters were not valid.\n", string.Empty))
            .On("networksetup -setdnsservers", args =>
            {
                dns[args[1]] = args[2] == "Empty" ? [] : args.Skip(2).ToArray();
                return new ProcessResult(0, string.Empty, string.Empty);
            })
            .On("scutil --dns", Scutil);

        var configurator = new MacDnsConfigurator(runner, Path.Combine(temp.Path, "backup.json"));
        var result = configurator.Redirect();

        Assert.True(result.Changed, result.Error);
        Assert.Equal(["Ethernet", "Wi-Fi"], result.Services);
        Assert.Equal(["127.0.0.1"], dns["Ethernet"]);
        Assert.Equal(["127.0.0.1"], dns["Wi-Fi"]);
        Assert.Equal(["1.0.0.1"], dns["Bluetooth PAN"]);
        Assert.Contains("dscacheutil -flushcache", runner.Calls);

        // Upstreams come from the backup once the system itself points at loopback.
        runner.On("scutil --dns", "DNS configuration\nresolver #1\n  nameserver[0] : 127.0.0.1\n");
        Assert.Equal(
            [new IPEndPoint(IPAddress.Parse("192.168.64.1"), 53), new IPEndPoint(IPAddress.Parse("2001:db8::53"), 53), new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53), new IPEndPoint(IPAddress.Parse("9.9.9.9"), 53)],
            configurator.DiscoverUpstreams());

        // A second redirect (daemon restart) keeps the original servers in the backup.
        configurator.Redirect();
        Assert.Equal(["9.9.9.9"], configurator.ReadBackup()!.Services.Single(service => service.Name == "Wi-Fi").Servers);

        Assert.True(configurator.RestoreIfNeeded());
        Assert.Empty(dns["Ethernet"]);
        Assert.Equal(["9.9.9.9"], dns["Wi-Fi"]);
        Assert.Null(configurator.ReadBackup());
        Assert.False(configurator.RestoreIfNeeded());
    }

    [Fact]
    public void RestoreWithoutBackupResetsLoopbackServicesToAutomatic()
    {
        using var temp = new TempDirectory();
        var dns = new Dictionary<string, string[]> { ["Ethernet"] = ["127.0.0.1"], ["Wi-Fi"] = ["8.8.8.8"] };
        var runner = new FakeRunner()
            .On("networksetup -listallnetworkservices", "Ethernet\nWi-Fi\n")
            .On("networksetup -getdnsservers", args => new ProcessResult(0, string.Join('\n', dns[args[1]]), string.Empty))
            .On("networksetup -setdnsservers", args =>
            {
                dns[args[1]] = args[2] == "Empty" ? [] : args.Skip(2).ToArray();
                return new ProcessResult(0, string.Empty, string.Empty);
            });

        Assert.True(new MacDnsConfigurator(runner, Path.Combine(temp.Path, "none.json")).RestoreIfNeeded());
        Assert.Empty(dns["Ethernet"]);
        Assert.Equal(["8.8.8.8"], dns["Wi-Fi"]);
        Assert.Contains("networksetup -setdnsservers Ethernet Empty", runner.Calls);
    }

    [Fact]
    public void RestoreRetriesUnreadableServicesAndFallsBackToTheBackup()
    {
        using var temp = new TempDirectory();
        var dns = new Dictionary<string, string[]> { ["Ethernet"] = ["10.0.2.3"], ["Wi-Fi"] = ["9.9.9.9"] };
        var failEthernetReads = 0;
        var failWifiAlways = false;
        var runner = new FakeRunner()
            .On("networksetup -listallnetworkservices", "Ethernet\nWi-Fi\n")
            .On("networksetup -getdnsservers", args =>
            {
                if ((args[1] == "Ethernet" && failEthernetReads-- > 0) || (args[1] == "Wi-Fi" && failWifiAlways))
                {
                    return new ProcessResult(4, string.Empty, "** Error: unable to read the configuration.");
                }

                return new ProcessResult(0, string.Join('\n', dns[args[1]]), string.Empty);
            })
            .On("networksetup -setdnsservers", args =>
            {
                dns[args[1]] = args[2] == "Empty" ? [] : args.Skip(2).ToArray();
                return new ProcessResult(0, string.Empty, string.Empty);
            })
            .On("scutil --dns", Scutil);
        var configurator = new MacDnsConfigurator(runner, Path.Combine(temp.Path, "backup.json"))
        {
            ReadRetryDelay = TimeSpan.Zero,
        };

        Assert.True(configurator.Redirect().Changed);

        // Two failed reads are retried; the service is still restored.
        failEthernetReads = 2;
        // A service that stays unreadable is restored from the backup, and the backup is kept.
        failWifiAlways = true;
        Assert.True(configurator.RestoreIfNeeded());
        Assert.Equal(["10.0.2.3"], dns["Ethernet"]);
        Assert.Equal(["9.9.9.9"], dns["Wi-Fi"]);
        Assert.NotNull(configurator.ReadBackup());

        failWifiAlways = false;
        configurator.RestoreIfNeeded();
        Assert.Null(configurator.ReadBackup());
    }

    [Fact]
    public void PlatformDoesNotRedirectForNonStandardPort()
    {
        using var temp = new TempDirectory();
        var runner = new FakeRunner();
        var platform = new MacPrivacyDnsPlatform(new MacDnsConfigurator(runner, Path.Combine(temp.Path, "b.json")), null);

        Assert.Contains("port 5353", platform.OnResolverStarted(5353), StringComparison.Ordinal);
        Assert.Empty(runner.Calls);
    }

    /// <summary>
    /// Upstream v0.23.3 adapter persistence (PreferredAdapterAlias / AutoPointAdapterDns) is Windows
    /// only. On macOS the seam member is the default no-op: no networksetup/scutil call is made for
    /// these settings, whatever their value, and the platform does not claim the feature.
    /// </summary>
    [Fact]
    public void AdapterDnsPersistenceSettingsNeverTouchSystemDns()
    {
        using var temp = new TempDirectory();
        var runner = new FakeRunner();
        IPrivacyDnsPlatform platform = new MacPrivacyDnsPlatform(
            new MacDnsConfigurator(runner, Path.Combine(temp.Path, "b.json")), null);

        platform.EnsureConfiguredAdapterDns(
            true,
            new PrivacyShieldSettings { Enabled = true, Port = 53, AutoPointAdapterDns = true, PreferredAdapterAlias = "Wi-Fi" });
        platform.EnsureConfiguredAdapterDns(false, new PrivacyShieldSettings { AutoPointAdapterDns = true, AutoUpdateSources = true });

        Assert.False(platform.SupportsAdapterDnsPersistence);
        Assert.Empty(runner.Calls);
        Assert.False(File.Exists(Path.Combine(temp.Path, "b.json")));
    }
}
