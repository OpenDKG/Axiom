// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Contracts.Ai;
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

        Assert.DoesNotContain("Community Feed", Section(Privacy, "(Off by Default)**"), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Community Feed", Section(Privacy, "On by Default After a Complete or Light Install**"), StringComparison.Ordinal);
        Assert.DoesNotContain("Starter feed is bundled and offline |", SecurityModel, StringComparison.Ordinal);
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
