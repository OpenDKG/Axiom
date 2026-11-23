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

    [Theory]
    [InlineData("safebrowsing.googleapis.com")]
    [InlineData("SafeBrowsing.GoogleApis.com.")]
    [InlineData("client.wns.windows.com")]
    [InlineData("ctldl.windowsupdate.com")]
    [InlineData("ocsp.digicert.com")]
    public void Catalog_lists_cannot_block_security_critical_domains(string domain)
    {
        var now = DateTimeOffset.UtcNow;
        var policy = PrivacyShieldPolicy.Create(
            new PrivacyShieldSettings(),
            [
                new PrivacyShieldStoredRule("safebrowsing.googleapis.com", "strict-list", PrivacyCategory.Tracking, now),
                new PrivacyShieldStoredRule("googleapis.com", "strict-list", PrivacyCategory.Tracking, now),
                new PrivacyShieldStoredRule("client.wns.windows.com", "strict-list", PrivacyCategory.Telemetry, now),
                new PrivacyShieldStoredRule("windowsupdate.com", "strict-list", PrivacyCategory.Telemetry, now),
                new PrivacyShieldStoredRule("digicert.com", "strict-list", PrivacyCategory.Tracking, now),
            ]);

        var decision = policy.Evaluate(domain);

        Assert.False(decision.Blocked);
        Assert.Equal("Security-critical domain; blocklists cannot block it.", decision.Reason);
    }

    [Fact]
    public void Catalog_parent_block_still_applies_to_unprotected_siblings()
    {
        var policy = PrivacyShieldPolicy.Create(
            new PrivacyShieldSettings(),
            [new PrivacyShieldStoredRule("googleapis.com", "strict-list", PrivacyCategory.Tracking, DateTimeOffset.UtcNow)]);

        Assert.True(policy.Evaluate("ads.googleapis.com").Blocked);
        Assert.False(policy.Evaluate("safebrowsing.googleapis.com").Blocked);
    }

    [Fact]
    public void User_block_rule_still_applies_to_security_critical_domain()
    {
        var policy = PrivacyShieldPolicy.Create(new PrivacyShieldSettings
        {
            BlockedDomains = ["client.wns.windows.com"],
        });

        Assert.True(policy.Evaluate("client.wns.windows.com").Blocked);
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

        // Only dedicated malware/phishing lists may claim the malware or phishing categories, so a
        // shared indicator is never an ad or tracker mislabelled as malware or phishing.
        var malware = sources
            .Where(source => source.Category.HasFlag(PrivacyCategory.Malware))
            .Select(source => (source.Id, source.Category))
            .ToArray();
        Assert.Equal(2, malware.Length);
        Assert.Contains(("urlhaus-domains", PrivacyCategory.Malware), malware);
        Assert.Contains(("hagezi-tif", PrivacyCategory.Malware | PrivacyCategory.Phishing), malware);

        var phishing = sources
            .Where(source => source.Category.HasFlag(PrivacyCategory.Phishing))
            .Select(source => (source.Id, source.Category))
            .ToArray();
        Assert.Equal(2, phishing.Length);
        Assert.Contains(("hagezi-tif", PrivacyCategory.Malware | PrivacyCategory.Phishing), phishing);
        Assert.Contains(("phishing-filter", PrivacyCategory.Phishing), phishing);

        Assert.True(PrivacyShieldCategories.ForProfile(PrivacyShieldProfile.Strict)
            .HasFlag(PrivacyCategory.Phishing));
        Assert.Equal("Phishing", PrivacyShieldCategories.Label(PrivacyCategory.Phishing));
    }

    [Fact]
    public void Rule_capacity_supports_all_catalogued_lists_and_auto_update_defaults()
    {
        Assert.True(PrivacyShieldPolicy.MaxRules >= 1_000_000);

        var defaults = new PrivacyShieldSettings();
        Assert.Equal(53, defaults.Port);
        Assert.True(defaults.AutoUpdateSources);
        Assert.Equal(24, defaults.AutoUpdateIntervalHours);
        Assert.Equal(string.Empty, defaults.PreferredAdapterAlias);
        Assert.False(defaults.AutoPointAdapterDns);
    }

    [Fact]
    public void With_settings_preserves_compiled_catalog_rules_across_category_and_allow_updates()
    {
        var initial = PrivacyShieldPolicy.Create(
            new PrivacyShieldSettings { Categories = PrivacyCategory.Ads },
            [
                new PrivacyShieldStoredRule("catalog.example", "hagezi-pro", PrivacyCategory.Ads, DateTimeOffset.UtcNow),
            ]);

        var updated = initial.WithSettings(new PrivacyShieldSettings
        {
            Categories = PrivacyCategory.None,
            AllowedDomains = ["sub.catalog.example"],
            BlockedDomains = ["custom-only.example"],
        });

        Assert.True(updated.Evaluate("catalog.example").Blocked);
        Assert.Equal("hagezi-pro", updated.Evaluate("catalog.example").SourceId);
        Assert.False(updated.Evaluate("sub.catalog.example").Blocked);
        Assert.True(updated.Evaluate("custom-only.example").Blocked);
        Assert.Equal(2, updated.RuleCount);

        using var reader = new StringReader("0.0.0.0 stream-a.example\nstream-b.example\n");
        var streamed = PrivacyShieldPolicy.ParseList(reader, 100);
        Assert.Equal(["stream-a.example", "stream-b.example"], streamed);
    }
}
