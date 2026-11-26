// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Privacy;
using Axiom.Presentation;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>In-app and documentation statements must match what the product does.</summary>
public sealed class StatementTruthTests
{
    [Theory]
    [InlineData(null, true, "SETTINGS ON")]
    [InlineData(null, false, "SHIELD ACTIVE")]
    [InlineData(false, true, "SETTINGS ON")]
    public void Home_headline_does_not_say_protected_without_a_verified_result(
        bool? verified, bool privacyShield, string badge)
    {
        var title = SimpleHomePageViewModel.ShieldOnTitle(verified, privacyShield);

        Assert.Equal("Protection settings on", title.Headline);
        Assert.Equal(badge, title.Badge);
    }

    [Theory]
    [InlineData(true, "Your computer is protected", "PROTECTED")]
    [InlineData(false, "Firewall Shield is protecting your apps", "SHIELD ACTIVE")]
    public void Home_headline_may_say_protected_with_a_verified_result(bool privacyShield, string headline, string badge)
    {
        var title = SimpleHomePageViewModel.ShieldOnTitle(verified: true, privacyShield);

        Assert.Equal((badge, headline), title);
    }

    [Fact]
    public void Disable_dialog_says_saved_decisions_are_removed_because_disabling_removes_them()
    {
        Assert.Contains("Decisions = [],", Read("src", "Axiom.Service", "ProtectionController.cs"), StringComparison.Ordinal);

        Assert.DoesNotContain("applies them again", FirewallPageViewModel.DisableShieldEffect, StringComparison.Ordinal);
        Assert.Contains("decisions are removed", FirewallPageViewModel.DisableShieldEffect, StringComparison.Ordinal);
    }

    [Fact]
    public void Test_vm_labels_are_gone_from_the_desktop_app()
    {
        foreach (var file in new[] { "ShellViewModel.cs", "FirewallPageViewModel.cs" })
        {
            Assert.DoesNotContain("test vm", Read("src", "Axiom.UI.Avalonia", file), StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void Install_mode_and_privacy_shield_text_match_setup()
    {
        var setup = Read("src", "Axiom.Setup", "SetupDefaults.cs");
        Assert.Contains("Profile = PrivacyShieldProfile.Strict,", setup, StringComparison.Ordinal);
        Assert.Contains("AutoPointAdapterDns = true,", setup, StringComparison.Ordinal);
        var options = Read("src", "Axiom.Setup", "SetupOptions.cs");
        Assert.Contains("EffectiveMode == SetupInstallMode.Optional ? EnableFirewallShield : true;", options, StringComparison.Ordinal);
        var sources = PrivacyShieldSourceCatalog.All.Count;
        Assert.Equal(8, sources);

        var readme = Flat(Read("README.md"));
        Assert.DoesNotContain("A **partial installation** leaves Shield off", readme, StringComparison.Ordinal);
        Assert.DoesNotContain("with the Balanced profile", readme, StringComparison.Ordinal);
        Assert.DoesNotContain("never changes adapter DNS", readme, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Five HTTPS sources", readme, StringComparison.Ordinal);
        Assert.Contains("A **Complete** or **Light / Partial** installation enables **Axiom Shield**", readme, StringComparison.Ordinal);
        Assert.Contains("turns it on with the Strict profile and all eight catalogued sources", readme, StringComparison.Ordinal);
        Assert.Contains("points the network adapters' DNS at the local resolver (`127.0.0.1`)", readme, StringComparison.Ordinal);

        var shield = Flat(Read("docs", "PRIVACY_SHIELD.md"));
        foreach (var withdrawn in new[]
                 {
                     "Balanced profile", "partial installation leaves it disabled", "Six sources",
                     "does not change Windows DNS settings", "no mode changes adapter DNS",
                 })
        {
            Assert.DoesNotContain(withdrawn, shield, StringComparison.OrdinalIgnoreCase);
        }

        Assert.Contains("Strict profile and all eight catalogued sources", shield, StringComparison.Ordinal);
    }

    [Fact]
    public void Support_page_text_matches_setup_and_the_write_gate()
    {
        // The Windows branches do not run on other platforms, so the page's source is read.
        var page = Read("src", "Axiom.UI.Avalonia", "SupportPageViewModel.cs");
        foreach (var withdrawn in new[]
                 {
                     "test-VM", "partial installation leaves it off", "Writes are off until you consent",
                     "never installed silently",
                 })
        {
            Assert.DoesNotContain(withdrawn, page, StringComparison.OrdinalIgnoreCase);
        }

        Assert.Contains(
            "(ProtectionWriteConsent.Granted && ProtectionWriteConsent.IsServiceHost)",
            Read("src", "Axiom.Core", "Firewall", "FirewallWriteGate.cs"),
            StringComparison.Ordinal);
        Assert.Contains("only while Axiom Shield is on", page, StringComparison.Ordinal);
        Assert.Contains("Complete and Light installs turn Shield on during setup", page, StringComparison.Ordinal);
        Assert.Contains("Complete and Light installs turn it on and point adapter DNS at it", page, StringComparison.Ordinal);
        Assert.Contains("A Complete install, the default in Windows Setup, includes them", page, StringComparison.Ordinal);
    }

    [Fact]
    public void Privacy_shield_document_says_the_installed_service_changes_adapter_dns()
    {
        Assert.Contains(
            "controller.EnsureConfiguredAdapterDns();",
            Read("src", "Axiom.Service", "PrivacyShieldWorker.cs"),
            StringComparison.Ordinal);
        Assert.Contains(
            "ensureAdapterPointed(settings.PreferredAdapterAlias);",
            Read("src", "Axiom.Infrastructure.Windows", "Dns", "WindowsPrivacyDnsPlatform.cs"),
            StringComparison.Ordinal);

        var shield = Flat(Read("docs", "PRIVACY_SHIELD.md"));
        foreach (var withdrawn in new[]
                 {
                     "never changes adapter DNS", "Automatic adapter DNS changes by the service itself",
                     "or by this module",
                 })
        {
            Assert.DoesNotContain(withdrawn, shield, StringComparison.OrdinalIgnoreCase);
        }

        Assert.Contains("points adapter DNS at `127.0.0.1` itself, without a prompt", shield, StringComparison.Ordinal);
        Assert.Contains("checks again every 30 seconds", shield, StringComparison.Ordinal);
    }

    [Fact]
    public void Architecture_states_the_real_history_retention_interval()
    {
        Assert.Contains(
            "RetentionInterval = TimeSpan.FromHours(6);",
            Read("src", "Axiom.Service", "HistoryWriter.cs"),
            StringComparison.Ordinal);

        Assert.Contains("retention at startup and every 6 hours", Read("docs", "ARCHITECTURE.md"), StringComparison.Ordinal);
    }

    [Fact]
    public void Readme_does_not_promise_that_every_protected_label_is_verified()
    {
        var readme = Flat(Read("README.md"));

        Assert.DoesNotContain("It never shows \"Protected\" unless", readme, StringComparison.Ordinal);
        Assert.Contains("the Home headline says protected only with a verified OS result", readme, StringComparison.Ordinal);
    }

    [Fact]
    public void Notices_list_every_catalogued_blocklist_with_its_license()
    {
        var notices = Read("THIRD_PARTY_NOTICES.md");

        Assert.All(PrivacyShieldSourceCatalog.All, source =>
            Assert.Contains($"| {source.Name} | {source.License} |", notices, StringComparison.Ordinal));
    }

    [Fact]
    public void Urlhaus_notice_states_the_conditions_on_the_underlying_data()
    {
        var row = Read("THIRD_PARTY_NOTICES.md").Split('\n')
            .Single(line => line.StartsWith("| URLhaus malicious domains |", StringComparison.Ordinal));

        foreach (var required in new[]
                 {
                     "(https://abuse.ch/terms-of-use/)", "commercial use may need a paid Spamhaus subscription",
                     "bar AI training on the data without", "covers Feodo Tracker, SSL Blacklist and YARAify, not URLhaus",
                 })
        {
            Assert.Contains(required, row, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Blocklist_text_matches_the_updater_and_promises_nothing_about_feed_terms()
    {
        var updater = Read("src", "Axiom.Service", "PrivacyShieldSourceUpdater.cs");
        Assert.Contains("MaxBytes = 20 * 1024 * 1024;", updater, StringComparison.Ordinal);
        Assert.Contains("Timeout = TimeSpan.FromMinutes(3),", updater, StringComparison.Ordinal);
        Assert.Equal(1_000_000, PrivacyShieldPolicy.MaxRules);

        var shield = Flat(Read("docs", "PRIVACY_SHIELD.md"));
        foreach (var withdrawn in new[] { "six HTTPS-only", "45 s bound", "500,000", "only if every selected source succeeds" })
        {
            Assert.DoesNotContain(withdrawn, shield, StringComparison.OrdinalIgnoreCase);
        }

        Assert.Contains("1,000,000 unique domains", shield, StringComparison.Ordinal);
        foreach (var text in new[] { shield, Flat(Read("README.md")) })
        {
            Assert.DoesNotContain("no separate approval is required", text, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("the original feeds can set their own terms", text, StringComparison.Ordinal);
        }
    }

    private static string Flat(string text) =>
        System.Text.RegularExpressions.Regex.Replace(text, @"\s+", " ");

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
