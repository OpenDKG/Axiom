// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Contracts.Ai;
using Axiom.Contracts.Privacy;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

/// <summary>
/// The privacy documents must describe the shipped defaults. Each test reads the default from the
/// product and the statement from the document, so changing one without the other fails.
/// </summary>
public sealed class PrivacyDocConsistencyTests
{
    private static readonly string Privacy = Read("PRIVACY.md");
    private static readonly string SecurityModel = Read("docs", "SECURITY_MODEL.md");
    private static readonly string Readme = Read("README.md");

    [Fact]
    public void Documents_do_not_name_a_default_ai_provider_the_product_does_not_have()
    {
        var defaults = new AiAnalystSettings();
        Assert.NotEqual(AiProviderKind.LocalOpenAiCompatible, defaults.Provider);
        Assert.Empty(defaults.Endpoint);

        Assert.DoesNotContain("Ollama (`http://localhost:11434`) by default", Privacy, StringComparison.Ordinal);
        Assert.DoesNotContain("defaults to local Ollama", SecurityModel, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("no AI provider endpoint or model is configured by default", Privacy, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Community_feed_written_as_enabled_is_not_documented_as_off_by_default()
    {
        var root = Directory.CreateTempSubdirectory("axiom-privacy-doc-").FullName;
        try
        {
            PrivacyShieldProvisioner.WriteSettings(root);
            using var feed = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "Axiom", "community-feed.json")));
            Assert.True(feed.RootElement.GetProperty("enabled").GetBoolean());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }

        // Setup writes the same file; the Windows Setup project has no test project.
        Assert.Contains("enabled = true,", Read("src", "Axiom.Setup", "SetupDefaults.cs"), StringComparison.Ordinal);

        // The claim must be where it belongs, and in no item that is headed "Off by Default".
        Assert.Contains(
            "**Community Feed:** Setup saves the feed as enabled",
            Section(Privacy, "On by Default After a Complete or Light Install**"),
            StringComparison.Ordinal);
        var offByDefault = Items(Privacy).Where(item => FirstLine(item).EndsWith("Off by Default)**", StringComparison.Ordinal)).ToList();
        Assert.Equal(2, offByDefault.Count);
        Assert.All(offByDefault, item => Assert.DoesNotContain("Community Feed", item, StringComparison.OrdinalIgnoreCase));
        Assert.Contains(
            "| Community feed | **Enabled by a Complete or Light install**", SecurityModel, StringComparison.Ordinal);
    }

    [Fact]
    public void Update_check_default_and_interval_match_the_product()
    {
        var missing = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Assert.True(new UpdateSettingsStore(missing).Load().CheckForUpdates);
        var minutes = (int)UpdateCheckService.MinimumCheckInterval.TotalMinutes;
        // The desktop shell's timer uses that same interval.
        Assert.Contains(
            "_updateTimer = timers.Create(UpdateCheckService.MinimumCheckInterval);",
            Read("src", "Axiom.UI.Avalonia", "ShellViewModel.cs"),
            StringComparison.Ordinal);

        var item = Section(Privacy, "Release Update Checks (On by Default, Toggleable)**");
        Assert.Contains($"on startup, every {minutes} minutes", item, StringComparison.Ordinal);
        var row = Row(SecurityModel, "| Release update check |");
        Assert.Contains("Enabled by default", row, StringComparison.Ordinal);
        Assert.Contains($"on startup & every {minutes} min ", row, StringComparison.Ordinal);
    }

    [Fact]
    public void Blocklist_update_schedule_matches_the_product()
    {
        var profile = PrivacyShieldProvisioner.CompleteProfileSettings();
        Assert.True(profile.AutoUpdateSources);
        var hours = profile.AutoUpdateIntervalHours;
        Assert.Equal(new PrivacyShieldSettings().AutoUpdateIntervalHours, hours);
        Assert.Contains(
            $"AutoUpdateIntervalHours = {hours},", Read("src", "Axiom.Setup", "SetupDefaults.cs"), StringComparison.Ordinal);

        Assert.Contains(
            $"updated automatically every {hours} hours",
            Section(Privacy, "On by Default After a Complete or Light Install**"),
            StringComparison.Ordinal);
        Assert.Contains($"automatically every {hours} h", Row(SecurityModel, "| Blocklist update |"), StringComparison.Ordinal);
    }

    [Fact]
    public void Adapter_dns_pointing_in_the_complete_profile_is_disclosed()
    {
        Assert.True(PrivacyShieldProvisioner.CompleteProfileSettings().AutoPointAdapterDns);

        var onByDefault = Section(Privacy, "On by Default After a Complete or Light Install**");
        Assert.Contains("127.0.0.1", onByDefault, StringComparison.Ordinal);
        Assert.Contains("1.1.1.1", onByDefault, StringComparison.Ordinal);
        Assert.Contains("9.9.9.9", onByDefault, StringComparison.Ordinal);
    }

    [Fact]
    public void External_ai_evidence_is_not_described_as_only_a_redacted_summary()
    {
        Assert.DoesNotContain("only the prompt and redacted summary", Privacy, StringComparison.OrdinalIgnoreCase);
        foreach (var document in new[] { Privacy, SecurityModel })
        {
            Assert.Contains("command lines", document, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("gateway addresses", document, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("DNS suffix", document, StringComparison.OrdinalIgnoreCase);
        }

        Assert.DoesNotContain("sanitized process metadata", Readme, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Records_without_a_retention_limit_are_disclosed()
    {
        var retention = Section(Privacy, "Local Retention and User Deletion**");
        Assert.Contains("does not remove", retention, StringComparison.Ordinal);
        Assert.Contains("axiom.db", retention, StringComparison.Ordinal);
        Assert.Contains("rule_audit", retention, StringComparison.Ordinal);
        Assert.Contains("process-spawn-audit.jsonl", retention, StringComparison.Ordinal);
        Assert.Contains("no retention limit", retention, StringComparison.OrdinalIgnoreCase);
    }

    private static string Row(string document, string start) =>
        Assert.Single(document.Split('\n'), line => line.StartsWith(start, StringComparison.Ordinal));

    private static string FirstLine(string item) => item.Split('\n')[0].TrimEnd();

    private static IEnumerable<string> Items(string document) =>
        document.Split('\n')
            .Where(line => System.Text.RegularExpressions.Regex.IsMatch(line, @"^\d+\. \*\*"))
            .Select(line => Section(document, line.TrimEnd()));

    /// <summary>The numbered item whose title ends with <paramref name="title"/>, up to the next item or heading.</summary>
    private static string Section(string document, string title)
    {
        var lines = document.Split('\n');
        var start = Array.FindIndex(lines, line => line.TrimEnd().EndsWith(title, StringComparison.Ordinal));
        Assert.True(start >= 0, $"PRIVACY.md has no item titled '...{title}'");
        var body = lines.Skip(start + 1)
            .TakeWhile(line => !line.StartsWith('#') && !System.Text.RegularExpressions.Regex.IsMatch(line, @"^\d+\. "));
        return string.Join('\n', body.Prepend(lines[start]));
    }

    private static string Read(params string[] parts)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "PRIVACY.md")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return File.ReadAllText(Path.Combine([directory.FullName, .. parts])).Replace("\r\n", "\n", StringComparison.Ordinal);
    }
}
