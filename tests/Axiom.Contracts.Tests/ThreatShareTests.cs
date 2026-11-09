// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Threat;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class ThreatShareTests
{
    [Theory]
    [InlineData("domain", "Evil.Example.", "evil.example")]
    [InlineData("domain", "  ads.example.com  ", "ads.example.com")]
    [InlineData("url", "https://evil.example/path/", "https://evil.example/path")]
    [InlineData("ip", "8.8.8.8", "8.8.8.8")]
    [InlineData("hash", "ABC0123456789012345678901234567890123456789012345678901234567890", "abc0123456789012345678901234567890123456789012345678901234567890")]
    public void Normalize_accepts_and_canonicalizes_supported_indicators(
        string type,
        string value,
        string expected)
    {
        Assert.Equal(expected, ThreatShareVocabulary.Normalize(type, value));
    }

    [Theory]
    [InlineData("domain", "not-a-domain")]
    [InlineData("domain", "C:\\Users\\me\\app.exe")]
    [InlineData("domain", "readme.md")]
    [InlineData("url", "ftp://evil.example")]
    [InlineData("ip", "127.0.0.1")]
    [InlineData("ip", "192.168.1.10")]
    [InlineData("ip", "not-an-ip")]
    [InlineData("hash", "abc123")]
    [InlineData("wallet", "abc")]
    public void Normalize_rejects_invalid_or_unshareable_values(string type, string value)
    {
        Assert.Null(ThreatShareVocabulary.Normalize(type, value));
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
