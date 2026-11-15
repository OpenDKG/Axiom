// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Infrastructure.Windows.Dns;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

/// <summary>Windows-only adapter discovery filtering; parsing lives in Axiom.Service.Hosting.</summary>
public sealed class SystemDnsResolverTests
{
    [Fact]
    public void System_dns_filter_excludes_deprecated_site_local_ipv6_dummy_servers()
    {
        var input = new[]
        {
            IPAddress.Parse("192.168.0.1"),
            IPAddress.Parse("fec0:0:0:ffff::1"),
            IPAddress.Parse("fec0:0:0:ffff::2"),
            IPAddress.Parse("fec0:0:0:ffff::3"),
            IPAddress.Loopback,
            IPAddress.IPv6Loopback,
            IPAddress.Any,
            IPAddress.IPv6Any,
            IPAddress.Parse("1.1.1.1"),
        };

        var filtered = SystemDnsResolver.FilterSystemDnsAddresses(input);

        Assert.Equal(
            [
                new IPEndPoint(IPAddress.Parse("192.168.0.1"), 53),
                new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53),
            ],
            filtered);
    }

}
