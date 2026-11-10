// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class DohBypassDetectorTests : IDisposable
{
    private readonly string _root;
    private readonly string _localAppData;
    private readonly string _appData;

    public DohBypassDetectorTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "axiom-doh-" + Guid.NewGuid().ToString("N"));
        _localAppData = Path.Combine(_root, "Local");
        _appData = Path.Combine(_root, "Roaming");
        Directory.CreateDirectory(_localAppData);
        Directory.CreateDirectory(_appData);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public void Chrome_secure_dns_is_reported_with_its_template()
    {
        WriteChromium("Google", "Chrome", "Default", """
            {"dns_over_https":{"mode":"secure","templates":"https://dns.google/dns-query"}}
            """);

        var finding = Assert.Single(Detect());

        Assert.Equal("Chrome", finding.Application);
        Assert.Contains("Default", finding.Detail, StringComparison.Ordinal);
        Assert.Contains("secure DNS", finding.Detail, StringComparison.Ordinal);
        Assert.Contains("https://dns.google/dns-query", finding.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Chrome_automatic_without_a_template_is_not_flagged()
    {
        WriteChromium("Google", "Chrome", "Default", """
            {"dns_over_https":{"mode":"automatic"}}
            """);

        Assert.Empty(Detect());
    }

    [Fact]
    public void Chrome_automatic_with_a_custom_template_is_flagged()
    {
        WriteChromium("Google", "Chrome", "Default", """
            {"dns_over_https":{"mode":"automatic","templates":"https://doh.example/dns-query"}}
            """);

        var finding = Assert.Single(Detect());

        Assert.Contains("automatic", finding.Detail, StringComparison.Ordinal);
        Assert.Contains("https://doh.example/dns-query", finding.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Chrome_off_is_not_flagged()
    {
        WriteChromium("Google", "Chrome", "Default", """
            {"dns_over_https":{"mode":"off"}}
            """);

        Assert.Empty(Detect());
    }

    [Fact]
    public void Every_chromium_profile_is_named()
    {
        WriteChromium("Google", "Chrome", "Default", """
            {"dns_over_https":{"mode":"secure"}}
            """);
        WriteChromium("Google", "Chrome", "Profile 2", """
            {"dns_over_https":{"mode":"secure"}}
            """);

        var finding = Assert.Single(Detect());

        Assert.Contains("Default", finding.Detail, StringComparison.Ordinal);
        Assert.Contains("Profile 2", finding.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Chrome_and_edge_are_reported_separately()
    {
        WriteChromium("Google", "Chrome", "Default", """
            {"dns_over_https":{"mode":"secure"}}
            """);
        WriteChromium("Microsoft", "Edge", "Default", """
            {"dns_over_https":{"mode":"secure"}}
            """);

        var findings = Detect();

        Assert.Equal(2, findings.Count);
        Assert.Equal("Chrome", findings[0].Application);
        Assert.Equal("Edge", findings[1].Application);
    }

    [Theory]
    [InlineData(2, "plain-DNS fallback")]
    [InlineData(3, "only")]
    public void Firefox_trr_modes_that_leave_the_resolver_are_reported(int mode, string expected)
    {
        WriteFirefox("abc.default-release", $"""
            user_pref("network.trr.mode", {mode});
            user_pref("network.trr.uri", "https://mozilla.cloudflare-dns.com/dns-query");
            """);

        var finding = Assert.Single(Detect());

        Assert.Equal("Firefox", finding.Application);
        Assert.Contains(expected, finding.Detail, StringComparison.Ordinal);
        Assert.Contains("mozilla.cloudflare-dns.com", finding.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    public void Firefox_trr_off_is_not_flagged(int mode)
    {
        WriteFirefox("abc.default-release", $"""
            user_pref("network.trr.mode", {mode});
            """);

        Assert.Empty(Detect());
    }

    [Fact]
    public void Missing_browser_profiles_report_no_bypass()
    {
        Assert.Empty(Detect());
        Assert.Equal(
            DohBypassDetector.NoBypassText,
            DohBypassDetector.BuildWarningText(Detect()));
    }

    [Fact]
    public void Warning_text_names_the_browser_and_where_to_turn_it_off()
    {
        WriteChromium("Google", "Chrome", "Default", """
            {"dns_over_https":{"mode":"secure","templates":"https://dns.google/dns-query"}}
            """);

        var text = DohBypassDetector.BuildWarningText(Detect());

        Assert.Contains("Chrome", text, StringComparison.Ordinal);
        Assert.Contains("chrome://settings/security", text, StringComparison.Ordinal);
        Assert.Contains("edge://settings/privacy", text, StringComparison.Ordinal);
        Assert.Contains("DNS over HTTPS", text, StringComparison.Ordinal);
        Assert.DoesNotContain(DohBypassDetector.NoBypassText, text, StringComparison.Ordinal);
    }

    private IReadOnlyList<DohBypassFinding> Detect() =>
        DohBypassDetector.Detect(_localAppData, _appData);

    private void WriteChromium(string vendor, string product, string profile, string preferences)
    {
        var directory = Path.Combine(_localAppData, vendor, product, "User Data", profile);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "Preferences"), preferences);
    }

    private void WriteFirefox(string profile, string prefs)
    {
        var directory = Path.Combine(_appData, "Mozilla", "Firefox", "Profiles", profile);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "prefs.js"), prefs);
    }
}
