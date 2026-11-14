// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Sockets;
using System.Text;
using Axiom.Contracts.Privacy;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class PrivacyShieldTests
{
    [Fact]
    public async Task Enabled_controller_starts_and_stops_the_loopback_resolver()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-privacy-{Guid.NewGuid():N}.json");
        var rulesPath = Path.Combine(Path.GetTempPath(), $"axiom-privacy-rules-{Guid.NewGuid():N}.json");
        int port;
        using (var probe = new System.Net.Sockets.UdpClient(
                   new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0)))
        {
            port = ((System.Net.IPEndPoint)probe.Client.LocalEndPoint!).Port;
        }

        try
        {
            var store = new PrivacyShieldSettingsStore(path);
            await using var controller = new PrivacyShieldController(
                store,
                new PrivacyShieldRuleStore(rulesPath));
            var settings = new PrivacyShieldSettings
            {
                Enabled = true,
                Port = port,
                Categories = PrivacyCategory.None,
                BlockedDomains = ["blocked.example"],
            };

            var status = await controller.ConfigureAsync(settings, CancellationToken.None);

            Assert.True(status.Running);
            Assert.Equal("Active", status.State);
            Assert.Equal(port, status.Port);
            Assert.Equal(1, status.RuleCount);
        }
        finally
        {
            File.Delete(path);
            File.Delete(rulesPath);
        }
    }

    [Fact]
    public async Task Failed_reconfiguration_keeps_previous_resolver_and_persisted_settings()
    {
        var directory = CreateTemporaryDirectory();
        var path = Path.Combine(directory, "settings.json");
        int previousPort;
        int occupiedPort;
        using (var firstProbe = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
        using (var secondProbe = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
        {
            previousPort = ((IPEndPoint)firstProbe.Client.LocalEndPoint!).Port;
            occupiedPort = ((IPEndPoint)secondProbe.Client.LocalEndPoint!).Port;
        }

        using var blocker = new UdpClient(new IPEndPoint(IPAddress.Loopback, occupiedPort));
        var controller = new PrivacyShieldController(new PrivacyShieldSettingsStore(path));
        try
        {
            var first = await controller.ConfigureAsync(
                EnabledSettings(previousPort),
                CancellationToken.None);
            Assert.True(first.Running);
            Assert.Equal(previousPort, first.Port);

            var failed = await controller.ConfigureAsync(
                EnabledSettings(occupiedPort),
                CancellationToken.None);

            Assert.True(failed.Running);
            Assert.Equal(previousPort, failed.Port);
            Assert.True(failed.Enabled);
            Assert.Contains("previous resolver restored", failed.LastError, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(3, await QueryRcodeAsync(previousPort, "blocked.example"));

            var loaded = new PrivacyShieldSettingsStore(path).Load();
            Assert.True(loaded.Enabled);
            Assert.Equal(previousPort, loaded.Port);

            await using var recreated = new PrivacyShieldController(new PrivacyShieldSettingsStore(path));
            var reloaded = await recreated.GetStatusAsync(CancellationToken.None);
            Assert.True(reloaded.Settings.Enabled);
            Assert.Equal(previousPort, reloaded.Settings.Port);
        }
        finally
        {
            await controller.DisposeAsync();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Enabling_on_an_occupied_port_keeps_the_disabled_configuration()
    {
        var directory = CreateTemporaryDirectory();
        var path = Path.Combine(directory, "settings.json");
        var occupiedPort = ReservePort();
        using var blocker = new UdpClient(new IPEndPoint(IPAddress.Loopback, occupiedPort));
        var controller = new PrivacyShieldController(new PrivacyShieldSettingsStore(path));
        try
        {
            var failed = await controller.ConfigureAsync(
                EnabledSettings(occupiedPort),
                CancellationToken.None);

            Assert.False(failed.Running);
            Assert.False(failed.Enabled);
            Assert.Equal("Disabled", failed.State);
            Assert.Contains("disabled configuration was kept", failed.LastError, StringComparison.OrdinalIgnoreCase);

            var loaded = new PrivacyShieldSettingsStore(path).Load();
            Assert.False(loaded.Enabled);
            Assert.Equal(53, loaded.Port);

            await using var recreated = new PrivacyShieldController(new PrivacyShieldSettingsStore(path));
            var reloaded = await recreated.GetStatusAsync(CancellationToken.None);
            Assert.False(reloaded.Enabled);
            Assert.Equal("Disabled", reloaded.State);
        }
        finally
        {
            await controller.DisposeAsync();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Settings_write_failure_restores_the_previous_resolver()
    {
        var directory = CreateTemporaryDirectory();
        var path = Path.Combine(directory, "settings.json");
        var port = ReservePort();
        var controller = new PrivacyShieldController(new PrivacyShieldSettingsStore(path));
        try
        {
            var first = await controller.ConfigureAsync(
                EnabledSettings(port),
                CancellationToken.None);
            Assert.True(first.Running);

            PrivacyShieldStatus failed;
            using (new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                failed = await controller.ConfigureAsync(
                    EnabledSettings(port) with { BlockedDomains = ["changed.example"] },
                    CancellationToken.None);
            }

            Assert.True(failed.Running);
            Assert.Equal(port, failed.Port);
            Assert.Contains("previous resolver restored", failed.LastError, StringComparison.OrdinalIgnoreCase);

            var loaded = new PrivacyShieldSettingsStore(path).Load();
            Assert.True(loaded.Enabled);
            Assert.Equal(port, loaded.Port);
            Assert.Contains("blocked.example", loaded.BlockedDomains);
            Assert.DoesNotContain("changed.example", loaded.BlockedDomains);
        }
        finally
        {
            await controller.DisposeAsync();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Default_state_is_disabled_and_can_be_saved()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-privacy-{Guid.NewGuid():N}.json");
        try
        {
            var store = new PrivacyShieldSettingsStore(path);
            await using var controller = new PrivacyShieldController(store);

            var initial = await controller.GetStatusAsync(CancellationToken.None);
            Assert.Equal("Disabled", initial.State);
            Assert.False(initial.Enabled);
            Assert.False(initial.Running);
            Assert.Equal(0, initial.Queries);

            var settings = new PrivacyShieldSettings
            {
                Enabled = false,
                Profile = PrivacyShieldProfile.Basic,
                Categories = PrivacyCategory.Telemetry,
                BlockedDomains = ["custom.example"],
            };
            var configured = await controller.ConfigureAsync(settings, CancellationToken.None);

            Assert.Equal("Disabled", configured.State);
            Assert.Equal(PrivacyShieldProfile.Basic, configured.Settings.Profile);
            Assert.Contains("custom.example", configured.Settings.BlockedDomains);

            var loaded = new PrivacyShieldSettingsStore(path).Load();
            Assert.Equal(PrivacyShieldProfile.Basic, loaded.Profile);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Status_reports_cached_per_source_totals_across_repeated_polls()
    {
        var directory = CreateTemporaryDirectory();
        var rulesPath = Path.Combine(directory, "rules.json");
        var settingsPath = Path.Combine(directory, "settings.json");
        var updated = DateTimeOffset.UtcNow.AddHours(-1);
        var rules = new[]
        {
            new PrivacyShieldStoredRule("a.example", "hagezi-pro", PrivacyCategory.Ads, updated),
            new PrivacyShieldStoredRule(
                "b.example", "hagezi-pro", PrivacyCategory.Ads, updated.AddMinutes(5)),
            new PrivacyShieldStoredRule("c.example", "oisd-big", PrivacyCategory.Tracking, updated),
        };
        Assert.True(new PrivacyShieldRuleStore(rulesPath).Save(rules));
        Assert.True(new PrivacyShieldSettingsStore(settingsPath).Save(new PrivacyShieldSettings
        {
            Enabled = false,
            Categories = PrivacyCategory.None,
            EnabledSourceIds = ["hagezi-pro", "oisd-big"],
        }));

        try
        {
            await using var controller = new PrivacyShieldController(
                new PrivacyShieldSettingsStore(settingsPath),
                new PrivacyShieldRuleStore(rulesPath));

            var first = await controller.GetStatusAsync(CancellationToken.None);
            var second = await controller.GetStatusAsync(CancellationToken.None);

            var hagezi = first.Sources.Single(source => source.Id == "hagezi-pro");
            Assert.Equal(2, hagezi.Entries);
            Assert.True(hagezi.Enabled);
            Assert.Equal(updated.AddMinutes(5), hagezi.UpdatedUtc);

            var oisd = first.Sources.Single(source => source.Id == "oisd-big");
            Assert.Equal(1, oisd.Entries);
            Assert.True(oisd.Enabled);
            Assert.Equal(updated, oisd.UpdatedUtc);

            var unused = first.Sources.Single(source => source.Id == "blocklistproject-ads");
            Assert.Equal(0, unused.Entries);
            Assert.Null(unused.UpdatedUtc);
            Assert.False(unused.Enabled);

            Assert.Equal(
                first.Sources.Select(source => (source.Id, source.Entries, source.UpdatedUtc)),
                second.Sources.Select(source => (source.Id, source.Entries, source.UpdatedUtc)));
            Assert.Equal(3, second.RuleCount);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Controller_accepts_doh_urls_and_upgrades_public_resolver_ips()
    {
        var directory = CreateTemporaryDirectory();
        var settingsPath = Path.Combine(directory, "settings.json");
        var rulesPath = Path.Combine(directory, "rules.json");
        var port = ReservePort();
        await using var controller = new PrivacyShieldController(
            new PrivacyShieldSettingsStore(settingsPath),
            new PrivacyShieldRuleStore(rulesPath));

        try
        {
            var byIp = await controller.ConfigureAsync(
                EnabledSettings(port) with { UpstreamDns = "1.1.1.1" },
                CancellationToken.None);
            Assert.True(byIp.Running);
            Assert.Contains("https://1.1.1.1/dns-query (DoH)", byIp.Upstream, StringComparison.Ordinal);

            var byUrl = await controller.ConfigureAsync(
                EnabledSettings(port) with { UpstreamDns = "https://dns.google/dns-query" },
                CancellationToken.None);
            Assert.True(byUrl.Running);
            Assert.Contains("https://dns.google/dns-query (DoH)", byUrl.Upstream, StringComparison.Ordinal);

            var rejected = await controller.ConfigureAsync(
                EnabledSettings(port) with { UpstreamDns = "https://localhost/dns-query" },
                CancellationToken.None);
            Assert.Contains("invalid", rejected.LastError, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Settings_persist_adapter_preferences_and_detect_missing_or_stale_sources()
    {
        var directory = CreateTemporaryDirectory();
        var port = ReservePort();
        var rulesPath = Path.Combine(directory, "privacy-shield-rules.json");
        var settingsPath = Path.Combine(directory, "privacy-shield.json");
        var staleTime = DateTimeOffset.UtcNow.AddHours(-30);
        var freshTime = DateTimeOffset.UtcNow.AddHours(-2);

        try
        {
            var store = new PrivacyShieldRuleStore(rulesPath);
            Assert.True(store.Save(
            [
                new PrivacyShieldStoredRule("ad.example", "hagezi-pro", PrivacyCategory.Ads, freshTime),
                new PrivacyShieldStoredRule("old.example", "oisd-big", PrivacyCategory.Ads, staleTime),
            ]));

            await using var first = new PrivacyShieldController(
                new PrivacyShieldSettingsStore(settingsPath),
                store);
            await first.StartAsync(CancellationToken.None);

            var status = await first.ConfigureAsync(
                EnabledSettings(port) with
                {
                    PreferredAdapterAlias = "Ethernet 2",
                    AutoPointAdapterDns = true,
                    AutoUpdateSources = true,
                    AutoUpdateIntervalHours = 24,
                    EnabledSourceIds = ["hagezi-pro", "hagezi-tif"],
                },
                CancellationToken.None);

            Assert.Equal("Ethernet 2", status.Settings.PreferredAdapterAlias);
            Assert.True(status.Settings.AutoPointAdapterDns);
            Assert.True(status.Settings.AutoUpdateSources);
            Assert.Equal(24, status.Settings.AutoUpdateIntervalHours);
            // hagezi-tif has never been downloaded yet, so auto-update must trigger immediately.
            Assert.True(first.ShouldAutoUpdateSources());

            // Fresh single source: no auto-update required.
            await first.ConfigureAsync(
                status.Settings with
                {
                    EnabledSourceIds = ["hagezi-pro"],
                },
                CancellationToken.None);
            Assert.False(first.ShouldAutoUpdateSources());

            // Stale source (> 24h old): auto-update triggers again.
            await first.ConfigureAsync(
                status.Settings with
                {
                    EnabledSourceIds = ["hagezi-pro", "oisd-big"],
                },
                CancellationToken.None);
            Assert.True(first.ShouldAutoUpdateSources());

            await using var restarted = new PrivacyShieldController(
                new PrivacyShieldSettingsStore(settingsPath),
                store);
            await restarted.StartAsync(CancellationToken.None);
            var reloaded = await restarted.GetStatusAsync(CancellationToken.None);
            Assert.Equal("Ethernet 2", reloaded.Settings.PreferredAdapterAlias);
            Assert.True(reloaded.Settings.AutoPointAdapterDns);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Controller_defaults_empty_upstream_to_encrypted_doh_when_isp_privacy_is_enabled()
    {
        var directory = CreateTemporaryDirectory();
        var port = ReservePort();
        await using var controller = new PrivacyShieldController(
            new PrivacyShieldSettingsStore(Path.Combine(directory, "settings.json")),
            new PrivacyShieldRuleStore(Path.Combine(directory, "rules.json")));

        try
        {
            var autoDoh = await controller.ConfigureAsync(
                EnabledSettings(port) with
                {
                    UpstreamDns = string.Empty,
                    EncryptDnsViaDoh = true,
                },
                CancellationToken.None);
            Assert.True(autoDoh.Running);
            Assert.Contains("(DoH)", autoDoh.Upstream, StringComparison.Ordinal);
            Assert.Contains("encrypted with DoH", autoDoh.Detail, StringComparison.OrdinalIgnoreCase);

            var multiDoh = await controller.ConfigureAsync(
                EnabledSettings(port) with
                {
                    UpstreamDns = "1.1.1.1, 9.9.9.9",
                    EncryptDnsViaDoh = true,
                },
                CancellationToken.None);
            Assert.True(multiDoh.Running);
            Assert.Contains("https://1.1.1.1/dns-query (DoH)", multiDoh.Upstream, StringComparison.Ordinal);
            Assert.Contains("https://9.9.9.9/dns-query (DoH)", multiDoh.Upstream, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static PrivacyShieldSettings EnabledSettings(int port) => new()
    {
        Enabled = true,
        Port = port,
        Categories = PrivacyCategory.None,
        BlockedDomains = ["blocked.example"],
        UpstreamDns = "1.1.1.1",
    };

    private static int ReservePort()
    {
        using var probe = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.Client.LocalEndPoint!).Port;
    }

    private static string CreateTemporaryDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"axiom-privacy-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static async Task<int> QueryRcodeAsync(int port, string domain)
    {
        using var client = new UdpClient(AddressFamily.InterNetwork);
        client.Connect(IPAddress.Loopback, port);
        var query = BuildQuery(domain);
        await client.SendAsync(query, query.Length).ConfigureAwait(false);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var response = await client.ReceiveAsync(timeout.Token).ConfigureAwait(false);
        return response.Buffer[3] & 0x0F;
    }

    private static byte[] BuildQuery(string domain)
    {
        var query = new List<byte>
        {
            0x12, 0x34, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        };
        foreach (var label in domain.Split('.'))
        {
            query.Add((byte)label.Length);
            query.AddRange(Encoding.ASCII.GetBytes(label));
        }

        query.Add(0);
        query.Add(0);
        query.Add(1);
        query.Add(0);
        query.Add(1);
        return query.ToArray();
    }
}
