// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Text.RegularExpressions;
using Axiom.Service.Hosting.Dns;

namespace Axiom.Service.Hosting.Tests;

/// <summary>docs/PRIVACY_SHIELD.md must describe the transport the resolver actually selects.</summary>
public sealed class PrivacyShieldUpstreamDocTests
{
    private static readonly string Shield = Regex.Replace(Read("docs", "PRIVACY_SHIELD.md"), @"\s+", " ");

    [Fact]
    public void Document_does_not_say_encrypted_upstreams_are_unsupported()
    {
        Assert.DoesNotContain("DoH/DoT are not supported", Shield, StringComparison.Ordinal);
        Assert.DoesNotContain("keeps the current Windows DNS servers", Shield, StringComparison.Ordinal);
        Assert.DoesNotContain("forwards allowed UDP queries over UDP", Shield, StringComparison.Ordinal);
        Assert.Contains("DNS-over-TLS and DNS-over-QUIC upstreams are not supported", Shield, StringComparison.Ordinal);
    }

    [Fact]
    public void Setup_upstreams_and_listed_public_resolvers_use_doh_without_plain_fallback()
    {
        Assert.Contains(
            "UpstreamDns = PrivacyShieldPolicy.DefaultDohUpstream,",
            Read("src", "Axiom.Setup", "SetupDefaults.cs"),
            StringComparison.Ordinal);
        Assert.Contains(
            "DefaultDohUpstream = \"1.1.1.1, 9.9.9.9\";",
            Read("src", "Axiom.Contracts", "Privacy", "PrivacyShieldPolicy.cs"),
            StringComparison.Ordinal);
        Assert.Contains("Setup uses `1.1.1.1, 9.9.9.9`", Shield, StringComparison.Ordinal);

        string[] documented = ["1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "94.140.14.14", "94.140.15.15"];
        Assert.All(documented, address => Assert.Contains($"`{address}`", Shield, StringComparison.Ordinal));
        foreach (var entry in documented.Append("1.1.1.1, 9.9.9.9").Append("8.8.8.8:53"))
        {
            Assert.True(DnsUpstream.TryParseTargets(entry, out var targets), entry);
            Assert.All(targets, target =>
            {
                Assert.True(target.IsDoh, entry);
                Assert.False(target.FallbackToPlainAllowed, entry);
            });
        }
    }

    [Theory]
    [InlineData("https://resolver.example/dns-query", true)]
    [InlineData("192.168.1.1", false)]
    [InlineData("1.1.1.1:5353", false)]
    [InlineData("udp://1.1.1.1", false)]
    [InlineData("tcp://1.1.1.1", false)]
    public void Entry_forms_select_the_documented_transport(string entry, bool doh)
    {
        Assert.True(DnsUpstream.TryParseTarget(entry, out var target));
        Assert.Equal(doh, target!.IsDoh);
    }

    [Theory]
    [InlineData("tls://1.1.1.1")]
    [InlineData("quic://1.1.1.1")]
    [InlineData("127.0.0.1")]
    public void Dns_over_tls_quic_and_loopback_entries_are_rejected(string entry) =>
        Assert.False(DnsUpstream.TryParseTarget(entry, out _));

    [Fact]
    public void Empty_field_does_not_promise_the_system_resolver_while_encryption_is_on()
    {
        IPEndPoint[] router = [new(IPAddress.Parse("192.168.1.1"), 53)];

        Assert.Equal(DnsUpstream.DefaultDohTargets(), DnsUpstream.SelectSystemTargets(router, encryptDnsViaDoh: true));
        Assert.False(Assert.Single(DnsUpstream.SelectSystemTargets(router, encryptDnsViaDoh: false)).IsDoh);
        Assert.Contains("so a router, VPN or corporate resolver is not used", Shield, StringComparison.Ordinal);
        Assert.Contains("The checkbox affects only an empty field", Shield, StringComparison.Ordinal);
    }

    private static string Read(params string[] parts)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "PRIVACY.md")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return File.ReadAllText(Path.Combine([directory.FullName, .. parts]));
    }
}
