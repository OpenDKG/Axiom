// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Sockets;
using System.Text;
using Netpetra.Contracts.Privacy;
using Xunit;

namespace Netpetra.Service.Tests;

public sealed class PrivacyShieldTests
{
    [Fact]
    public async Task Enabled_controller_starts_and_stops_the_loopback_resolver()
    {
        var path = Path.Combine(Path.GetTempPath(), $"netpetra-privacy-{Guid.NewGuid():N}.json");
        int port;
        using (var probe = new System.Net.Sockets.UdpClient(
                   new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0)))
        {
            port = ((System.Net.IPEndPoint)probe.Client.LocalEndPoint!).Port;
        }

        try
        {
            var store = new PrivacyShieldSettingsStore(path);
            await using var controller = new PrivacyShieldController(store);
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
        var path = Path.Combine(Path.GetTempPath(), $"netpetra-privacy-{Guid.NewGuid():N}.json");
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
