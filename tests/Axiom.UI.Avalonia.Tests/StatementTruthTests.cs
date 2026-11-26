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
