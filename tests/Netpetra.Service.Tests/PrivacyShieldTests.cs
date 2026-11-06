// SPDX-License-Identifier: GPL-3.0-or-later
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
}
