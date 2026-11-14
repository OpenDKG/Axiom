// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Axiom.Presentation;

/// <summary>
/// Resolves the Hermes config file the Blackbox guard actually reads. On Windows the guard reads
/// <c>%LOCALAPPDATA%\hermes\config.yaml</c>; older installs used <c>~/.hermes/config.yaml</c>.
/// Writing block mode to the wrong file leaves the guard in audit, which looks installed but is not.
/// </summary>
public static class HermesConfigLocation
{
    /// <summary>Candidate paths, most authoritative first.</summary>
    public static IReadOnlyList<string> Candidates(string localAppData, string userProfile) =>
    [
        Path.Combine(localAppData, "hermes", "config.yaml"),
        Path.Combine(userProfile, ".hermes", "config.yaml"),
    ];

    /// <summary>The first existing candidate, or the authoritative default when none exists.</summary>
    public static string Resolve(string localAppData, string userProfile, Func<string, bool> fileExists)
    {
        var candidates = Candidates(localAppData, userProfile);
        foreach (var candidate in candidates)
        {
            if (fileExists(candidate))
            {
                return candidate;
            }
        }

        return candidates[0];
    }

    /// <summary>
    /// Sets the plugin mode, preserving every other line. Returns the original text when the file
    /// has no mode line inside the blackbox entry.
    /// </summary>
    public static string ApplyMode(string yaml, string mode)
    {
        if (string.IsNullOrEmpty(yaml))
        {
            return yaml;
        }

        var updated = Regex.Replace(
            yaml,
            @"(?m)^(\s*)mode:\s*(audit|block|flag)\s*$",
            "${1}mode: " + mode);

        if (!updated.Contains("mode:", StringComparison.Ordinal))
        {
            // No existing mode line: add one under the blackbox entry.
            updated = updated.Replace(
                "    blackbox:",
                "    blackbox:" + Environment.NewLine + "      mode: " + mode,
                StringComparison.Ordinal);
        }

        return updated;
    }

    /// <summary>True when the config text asks for block mode.</summary>
    public static bool IsBlockMode(string yaml) =>
        Regex.IsMatch(yaml ?? string.Empty, @"(?m)^\s*mode:\s*block\s*$");
}

/// <summary>One row of the post-install protection self-test.</summary>
public sealed record ProtectionCheck(string Name, bool ExpectBlock, string Tool, string Path);

/// <summary>Result of one executed check.</summary>
public sealed record ProtectionCheckResult(string Name, bool ExpectBlock, bool Blocked, string Identifier)
{
    public bool Passed => ExpectBlock == Blocked;
}

/// <summary>
/// Post-install proof that agent protection is real. A full install must not report success unless
/// a protected read and write are blocked and an ordinary read is allowed.
/// </summary>
public static class AgentProtectionSelfTest
{
    public static IReadOnlyList<ProtectionCheck> DefaultChecks() =>
    [
        new ProtectionCheck("allowed read", ExpectBlock: false, "read", @"C:\AxiomSelfTest\allowed.txt"),
        new ProtectionCheck("protected read", ExpectBlock: true, "read", @"C:\Users\lab\.ssh\id_rsa"),
        new ProtectionCheck("protected write", ExpectBlock: true, "write", @"C:\AxiomSelfTest\.env"),
    ];

    /// <summary>OpenCode-shaped bridge payload (the bridge translates filePath to path).</summary>
    public static string BuildPayload(ProtectionCheck check, string session) =>
        JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["framework"] = "opencode",
            ["tool"] = check.Tool,
            ["args"] = new Dictionary<string, object?>
            {
                ["filePath"] = check.Path,
                ["content"] = "AXIOM-SELF-TEST",
            },
            ["session"] = session,
            ["call"] = Guid.NewGuid().ToString("N")[..8],
        });

    /// <summary>True when the bridge's stdout is a block decision.</summary>
    public static bool IsBlock(string stdout)
    {
        if (string.IsNullOrWhiteSpace(stdout))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(stdout.Trim());
            return document.RootElement.TryGetProperty("action", out var action) &&
                   string.Equals(action.GetString(), "block", StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>Extracts the first graph identifier from the decision message, when present.</summary>
    public static string Identifier(string stdout)
    {
        var match = Regex.Match(stdout ?? string.Empty, @"(fileaccess:[a-z]+:[a-z-]+)");
        return match.Success ? match.Groups[1].Value : string.Empty;
    }

    public static bool AllPassed(IEnumerable<ProtectionCheckResult> results) => results.All(result => result.Passed);

    public static string Summary(IEnumerable<ProtectionCheckResult> results) =>
        string.Join("; ", results.Select(result =>
            $"{result.Name}={(result.Passed ? "PASS" : "FAIL")}" +
            (string.IsNullOrEmpty(result.Identifier) ? string.Empty : $" [{result.Identifier}]")));
}
