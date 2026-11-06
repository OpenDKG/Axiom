// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Netpetra.Contracts.Firewall;
using Netpetra.UI.Services;
using Xunit;

namespace Netpetra.UI.Tests;

public sealed class FirewallDefaultsStoreTests
{
    [Fact]
    public void Defaults_round_trip_and_event_fires()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-firewall-{Guid.NewGuid():N}.json");
        try
        {
            var store = new FirewallDefaultsStore(path);
            var raised = 0;
            store.Changed += (_, _) => raised++;

            var saved = store.Save(new FirewallDefaults(
                FirewallProfile.Private | FirewallProfile.Public,
                NetworkProtocol.Tcp,
                "443,8000-8100",
                "192.0.2.0/24"));

            Assert.True(saved);
            Assert.Equal(1, raised);

            var loaded = store.Load();
            Assert.Equal(FirewallProfile.Private | FirewallProfile.Public, loaded.Profiles);
            Assert.Equal(NetworkProtocol.Tcp, loaded.Protocol);
            Assert.Equal("443,8000-8100", loaded.RemotePorts);
            Assert.Equal("192.0.2.0/24", loaded.RemoteAddresses);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Invalid_defaults_are_rejected_and_do_not_create_a_file()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-firewall-{Guid.NewGuid():N}.json");
        try
        {
            var store = new FirewallDefaultsStore(path);
            var saved = store.Save(new FirewallDefaults(
                FirewallProfile.None,
                NetworkProtocol.Any,
                string.Empty,
                string.Empty));

            Assert.False(saved);
            Assert.False(File.Exists(path));
            Assert.Equal(FirewallDefaults.Default, store.Load());
        }
        finally
        {
            File.Delete(path);
        }
    }
}
