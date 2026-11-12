// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Threat;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class ThreatShareTests
{
    [Theory]
    [InlineData("domain", "Evil.Example.", "evil.example")]
    [InlineData("domain", "  ads.example.com  ", "ads.example.com")]
    [InlineData("url", "https://evil.example/", "https://evil.example")]
    [InlineData("url", "http://evil.example/?api_key=secret", "http://evil.example")]
    [InlineData("url", "https://bücher.example/", "https://xn--bcher-kva.example")]
    [InlineData("ip", "8.8.8.8", "8.8.8.8")]
    [InlineData("ip", "2001:4860:4860::8888", "2001:4860:4860::8888")]
    [InlineData("hash", "ABC0123456789012345678901234567890123456789012345678901234567890", "abc0123456789012345678901234567890123456789012345678901234567890")]
    public void Normalize_accepts_and_canonicalizes_supported_indicators(
        string type,
        string value,
        string expected)
    {
        Assert.Equal(expected, ThreatShareVocabulary.Normalize(type, value));
    }

    [Fact]
    public void Url_path_requires_explicit_opt_in_and_secrets_are_always_stripped()
    {
        Assert.Null(ThreatShareVocabulary.Normalize("url", "https://evil.example/private/doc?x=1"));
        Assert.Equal(
            "https://evil.example/private/doc",
            ThreatShareVocabulary.Normalize("url", "https://evil.example/private/doc?x=1", allowUrlPath: true));
        Assert.Null(
            ThreatShareVocabulary.Normalize("url", "https://user:pass@evil.example/private?token=1"));
        Assert.Equal(
            "https://evil.example",
            ThreatShareVocabulary.Normalize("url", "https://user:pass@evil.example/?token=1"));
    }

    [Theory]
    [InlineData("domain", "not-a-domain")]
    [InlineData("domain", "C:\\Users\\me\\app.exe")]
    [InlineData("domain", "readme.md")]
    [InlineData("url", "ftp://evil.example")]
    [InlineData("url", "https://evil.example/path/")]
    [InlineData("url", "https://user:pass@evil.example:8443/path?token=abc#frag")]
    [InlineData("url", "http://127.0.0.1:9700/api/session")]
    [InlineData("url", "http://192.168.1.5/admin")]
    [InlineData("url", "http://printer.local/status")]
    [InlineData("url", "http://intranet/status")]
    [InlineData("url", "https://[::1]/status")]
    [InlineData("ip", "127.0.0.1")]
    [InlineData("ip", "192.168.1.10")]
    [InlineData("ip", "not-an-ip")]
    [InlineData("hash", "abc123")]
    [InlineData("wallet", "abc")]
    public void Normalize_rejects_invalid_or_unshareable_values(string type, string value)
    {
        Assert.Null(ThreatShareVocabulary.Normalize(type, value));
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("100.64.0.1")]
    [InlineData("169.254.10.20")]
    [InlineData("192.0.0.8")]
    [InlineData("192.0.2.10")]
    [InlineData("192.31.196.5")]
    [InlineData("192.52.193.5")]
    [InlineData("192.175.48.5")]
    [InlineData("198.18.0.1")]
    [InlineData("198.51.100.7")]
    [InlineData("203.0.113.5")]
    [InlineData("224.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("::1")]
    [InlineData("::ffff:192.168.1.10")]
    [InlineData("64:ff9b::1.2.3.4")]
    [InlineData("100::1")]
    [InlineData("2001:db8::1")]
    [InlineData("2002::1")]
    [InlineData("3fff::1")]
    [InlineData("5f00::1")]
    [InlineData("fc00::1")]
    [InlineData("fe80::1")]
    [InlineData("ff02::1")]
    public void Normalize_rejects_special_purpose_and_mapped_addresses(string value)
    {
        Assert.Null(ThreatShareVocabulary.Normalize("ip", value));
    }

    [Fact]
    public void Vocabulary_allows_only_honest_contexts_and_known_reasons()
    {
        Assert.True(ThreatShareVocabulary.IsSupported("domain", "malware-delivery", "fetched-by-tool"));
        Assert.True(ThreatShareVocabulary.IsSupported("hash", "phishing", "in-tool-output"));

        // A DNS block alone has no honest agent context, and ads are not a threat reason.
        Assert.False(ThreatShareVocabulary.IsSupported("domain", "malware-delivery", "blocked-by-dns"));
        Assert.False(ThreatShareVocabulary.IsSupported("domain", "advertising", "fetched-by-tool"));
        Assert.False(ThreatShareVocabulary.IsSupported("wallet", "phishing", "in-tool-output"));
    }

    [Fact]
    public void Identifier_is_stable_for_the_same_indicator()
    {
        var first = ThreatShareVocabulary.Normalize("domain", "Evil.Example.");
        var second = ThreatShareVocabulary.Normalize("domain", "evil.example");

        Assert.NotNull(first);
        Assert.Equal(
            ThreatShareVocabulary.BuildId("domain", first!),
            ThreatShareVocabulary.BuildId("domain", second!));
        Assert.Equal("ioc:domain:evil.example", ThreatShareVocabulary.BuildId("domain", first!));
    }

    [Theory]
    [InlineData("opencode", "", true)]
    [InlineData("node", @"C:\Users\me\AppData\Local\Programs\opencode\opencode.exe", true)]
    [InlineData("python", @"C:\Users\me\.claude\claude.exe", true)]
    [InlineData("hermes.exe", "", true)]
    [InlineData("chrome", @"C:\Program Files\Google\Chrome\chrome.exe", false)]
    [InlineData("node", @"C:\Projects\my-app\server.js", false)]
    public void Agent_process_match_uses_the_name_or_a_known_install_path(
        string name,
        string path,
        bool expected)
    {
        Assert.Equal(expected, AgentProcessMatcher.IsAgentProcess(name, path));
    }
}
