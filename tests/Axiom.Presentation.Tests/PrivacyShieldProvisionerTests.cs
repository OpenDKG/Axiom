// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.Contracts.Community;
using Axiom.Contracts.Privacy;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class PrivacyShieldProvisionerTests
{
    [Fact]
    public void Complete_profile_uses_strict_every_category_and_every_source()
    {
        var settings = PrivacyShieldProvisioner.CompleteProfileSettings();

        Assert.True(settings.Enabled);
        Assert.Equal(PrivacyShieldProfile.Strict, settings.Profile);
        Assert.True(settings.Categories.HasFlag(PrivacyCategory.Telemetry));
        Assert.True(settings.Categories.HasFlag(PrivacyCategory.Malware));
        Assert.True(settings.Categories.HasFlag(PrivacyCategory.Custom));
        Assert.Equal(PrivacyShieldSourceCatalog.All.Count, settings.EnabledSourceIds.Count);
        Assert.Contains("urlhaus-domains", settings.EnabledSourceIds);
        Assert.Equal(53, settings.Port);
        Assert.Equal(PrivacyShieldPolicy.DefaultDohUpstream, settings.UpstreamDns);
        Assert.True(settings.EncryptDnsViaDoh);
        Assert.True(settings.AutoPointAdapterDns);
        Assert.True(settings.AutoUpdateSources);
        Assert.Equal(24, settings.AutoUpdateIntervalHours);
    }

    [Fact]
    public void WriteSettings_creates_files_the_service_reads()
    {
        var root = Path.Combine(Path.GetTempPath(), $"axiom-privacy-{Guid.NewGuid():N}");
        try
        {
            PrivacyShieldProvisioner.WriteSettings(root);

            var shield = File.ReadAllText(Path.Combine(root, "Axiom", "privacy-shield.json"));
            var feed = File.ReadAllText(Path.Combine(root, "Axiom", "community-feed.json"));

            Assert.True(PrivacyShieldProvisioner.IsCompleteProfile(shield));
            Assert.Contains("axiom://starter", feed, StringComparison.Ordinal);
            Assert.Contains(CommunityFeedCatalog.RecommendedBundleUrl, feed, StringComparison.Ordinal);
            Assert.Contains("\"enabled\": true", feed, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("", false)]
    [InlineData("{}", false)]
    [InlineData("""{"enabled":true,"profile":1,"enabledSourceIds":["x"]}""", false)]
    [InlineData("""{"enabled":true,"profile":2,"enabledSourceIds":["x"]}""", true)]
    [InlineData("""{"enabled":false,"profile":2,"enabledSourceIds":["x"]}""", false)]
    public void IsCompleteProfile_requires_strict_enabled_with_sources(string json, bool expected)
    {
        Assert.Equal(expected, PrivacyShieldProvisioner.IsCompleteProfile(json));
    }
}
