// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Privacy;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class PrivacyShieldPolicyTests
{
    [Fact]
    public void Domain_normalization_handles_case_and_trailing_dot()
    {
        Assert.Equal("example.com", PrivacyShieldPolicy.NormalizeDomain(" Example.COM. "));
        Assert.Equal("xn--bcher-kva.example", PrivacyShieldPolicy.NormalizeDomain("bücher.example"));
        Assert.Null(PrivacyShieldPolicy.NormalizeDomain("127.0.0.1"));
        Assert.Null(PrivacyShieldPolicy.NormalizeDomain(""));
        Assert.Null(PrivacyShieldPolicy.NormalizeDomain("-bad.example"));
    }

    [Fact]
    public void List_parser_supports_hosts_wildcards_and_comments()
    {
        var domains = PrivacyShieldPolicy.ParseList("""
            # comment
            0.0.0.0 ads.example
            127.0.0.1 tracker.example # inline
            *.wild.example
            ||adblock.example^
            bad..example
            advertisements.example
            """);

        Assert.Equal(
            ["ads.example", "tracker.example", "wild.example", "adblock.example", "advertisements.example"],
            domains);
    }

    [Fact]
    public void Single_label_domains_are_rejected()
    {
        Assert.Null(PrivacyShieldPolicy.NormalizeDomain("com"));
        Assert.Null(PrivacyShieldPolicy.NormalizeDomain("localhost"));
        Assert.Equal("example.com", PrivacyShieldPolicy.NormalizeDomain("example.com"));
        Assert.Empty(PrivacyShieldPolicy.ParseList("com\nlocalhost\n"));
    }

    [Fact]
    public void HaGeZi_source_is_pinned_to_a_commit_with_a_digest()
    {
        var pro = Assert.Single(PrivacyShieldSourceCatalog.All, item => item.Id == "hagezi-pro");
        var tif = Assert.Single(PrivacyShieldSourceCatalog.All, item => item.Id == "hagezi-tif");

        foreach (var source in new[] { pro, tif })
        {
            Assert.Contains("@924bb2a8306e609ae8b0113c2b676f5fde072d16", source.Url, StringComparison.Ordinal);
            Assert.Equal(64, source.Sha256.Length);
            Assert.DoesNotContain("@latest", source.Url, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Allow_rule_wins_over_starter_block_rule()
    {
        var policy = PrivacyShieldPolicy.Create(new PrivacyShieldSettings
        {
            Categories = PrivacyCategory.Ads,
            AllowedDomains = ["doubleclick.net"],
        });

        var decision = policy.Evaluate("ads.doubleclick.net");

        Assert.False(decision.Blocked);
        Assert.Equal("Matched an allow rule.", decision.Reason);
    }

    [Fact]
    public void Profile_categories_control_starter_rules()
    {
        var basic = PrivacyShieldPolicy.Create(new PrivacyShieldSettings
        {
            Categories = PrivacyShieldCategories.ForProfile(PrivacyShieldProfile.Basic),
        });
        Assert.True(basic.Evaluate("v10.events.data.microsoft.com").Blocked);
        Assert.False(basic.Evaluate("doubleclick.net").Blocked);

        var balanced = PrivacyShieldPolicy.Create(new PrivacyShieldSettings
        {
            Categories = PrivacyShieldCategories.ForProfile(PrivacyShieldProfile.Balanced),
        });
        Assert.True(balanced.Evaluate("ads.doubleclick.net").Blocked);
        Assert.Equal(PrivacyCategory.Ads, balanced.Evaluate("doubleclick.net").Category);
    }

    [Fact]
    public void Custom_domains_block_their_subdomains()
    {
        var policy = PrivacyShieldPolicy.Create(new PrivacyShieldSettings
        {
            Categories = PrivacyCategory.None,
            BlockedDomains = ["custom.example"],
            AllowedDomains = ["safe.custom.example"],
        });

        Assert.True(policy.Evaluate("deep.custom.example").Blocked);
        Assert.False(policy.Evaluate("safe.custom.example").Blocked);
        Assert.False(policy.Evaluate("other.example").Blocked);
    }

    [Fact]
    public void Block_decision_carries_the_matching_source_for_local_provenance()
    {
        var policy = PrivacyShieldPolicy.Create(
            new PrivacyShieldSettings { Categories = PrivacyCategory.None },
            [
                new PrivacyShieldStoredRule(
                    "evil.example",
                    "urlhaus-domains",
                    PrivacyCategory.Malware,
                    DateTimeOffset.UtcNow),
            ]);

        var decision = policy.Evaluate("deep.evil.example");

        Assert.True(decision.Blocked);
        Assert.Equal("evil.example", decision.MatchedRule);
        Assert.Equal("urlhaus-domains", decision.SourceId);
        Assert.Equal(PrivacyCategory.Malware, decision.Category);
    }

    [Fact]
    public void Source_catalog_has_eight_license_cleared_entries()
    {
        var sources = PrivacyShieldSourceCatalog.All;

        Assert.Equal(8, sources.Count);
        Assert.Equal(
            sources.Count,
            sources.Select(source => source.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(sources, source => Assert.True(
            source.License is "GPL-3.0" or "MIT" or "Unlicense",
            source.License));
        Assert.All(sources, source => Assert.StartsWith("https://", source.Url, StringComparison.Ordinal));

        // Only dedicated malware/phishing lists may claim the malware category, so a shared
        // indicator is never an ad or tracker mislabelled as malware.
        var malware = sources
            .Where(source => source.Category.HasFlag(PrivacyCategory.Malware))
            .Select(source => (source.Id, source.Category))
            .ToArray();
        Assert.Equal(3, malware.Length);
        Assert.Contains(("urlhaus-domains", PrivacyCategory.Malware), malware);
        Assert.Contains(("hagezi-tif", PrivacyCategory.Malware), malware);
        Assert.Contains(("phishing-filter", PrivacyCategory.Malware), malware);
    }
}
