// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Windows.Dns;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

public sealed class DnsAdapterSnapshotTests
{
    private static readonly string[] RouterDns = ["192.168.0.1"];

    private const string Snapshot = """
        {
          "capturedUtc": "2026-11-10T00:00:00.0000000+00:00",
          "machine": "TEST",
          "interfaces": [
            {
              "interfaceAlias": "Ethernet 2",
              "interfaceIndex": 6,
              "addressFamily": 2,
              "serverAddresses": [ "192.168.0.1" ]
            },
            {
              "interfaceAlias": "Wi-Fi",
              "interfaceIndex": 9,
              "addressFamily": 2,
              "serverAddresses": []
            }
          ]
        }
        """;

    [Fact]
    public void Reads_the_saved_servers_for_an_adapter_ignoring_case()
    {
        var path = WriteSnapshot(Snapshot);
        try
        {
            Assert.True(DnsAdapterSnapshot.TryReadServerAddresses(path, "ethernet 2", out var addresses));
            Assert.Equal(RouterDns, addresses);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void An_empty_server_list_means_the_adapter_used_automatic_dns()
    {
        var path = WriteSnapshot(Snapshot);
        try
        {
            Assert.True(DnsAdapterSnapshot.TryReadServerAddresses(path, "Wi-Fi", out var addresses));
            Assert.Empty(addresses);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Unknown_adapter_yields_no_fallback()
    {
        var path = WriteSnapshot(Snapshot);
        try
        {
            Assert.False(DnsAdapterSnapshot.TryReadServerAddresses(path, "Ethernet 3", out var addresses));
            Assert.Empty(addresses);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Missing_or_broken_snapshot_is_not_an_error()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"axiom-missing-{Guid.NewGuid():N}.json");
        Assert.False(DnsAdapterSnapshot.TryReadServerAddresses(missing, "Ethernet 2", out _));

        var broken = WriteSnapshot("{ not json");
        try
        {
            Assert.False(DnsAdapterSnapshot.TryReadServerAddresses(broken, "Ethernet 2", out _));
        }
        finally
        {
            File.Delete(broken);
        }
    }

    private static string WriteSnapshot(string json)
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-dns-snapshot-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, json);
        return path;
    }
}
