// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Axiom.Presentation;

/// <summary>One browser that can resolve names without asking the Axiom resolver.</summary>
public sealed record DohBypassFinding(string Application, string Detail);

/// <summary>
/// Read-only detection of browser DNS-over-HTTPS settings. Chrome and Edge keep the decision in
/// <c>User Data\&lt;profile&gt;\Preferences</c> (<c>dns_over_https.mode</c>) and Firefox in
/// <c>prefs.js</c> (<c>network.trr.mode</c>). Nothing here writes to a browser profile or registry.
/// </summary>
public static class DohBypassDetector
{
    public const string NoBypassText =
        "No browser secure-DNS (DoH) override found in the Chrome, Edge or Firefox profiles. " +
        "Windows system DoH is not checked here: it applies to a public DNS server, and an adapter " +
        "pointed at 127.0.0.1 has no DoH template.";

    private static readonly Regex TrrModePattern = new(
        "user_pref\\(\\s*\"network\\.trr\\.mode\"\\s*,\\s*(\\d+)\\s*\\)\\s*;",
        RegexOptions.Compiled);

    private static readonly Regex TrrUriPattern = new(
        "user_pref\\(\\s*\"network\\.trr\\.uri\"\\s*,\\s*\"([^\"]*)\"\\s*\\)\\s*;",
        RegexOptions.Compiled);

    public static IReadOnlyList<DohBypassFinding> Detect(
        string? localAppData = null,
        string? appData = null)
    {
        localAppData ??= Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        appData ??= Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var findings = new List<DohBypassFinding>();
        AddChromium(findings, "Chrome", Path.Combine(localAppData, "Google", "Chrome", "User Data"));
        AddChromium(findings, "Edge", Path.Combine(localAppData, "Microsoft", "Edge", "User Data"));
        AddFirefox(findings, Path.Combine(appData, "Mozilla", "Firefox", "Profiles"));
        return findings;
    }

    /// <summary>
    /// Warning text for the Privacy Shield page. It says what was found, that the browser leaves the
    /// resolver, and exactly where each browser turns secure DNS off.
    /// </summary>
    public static string BuildWarningText(IReadOnlyList<DohBypassFinding> findings)
    {
        if (findings.Count == 0)
        {
            return NoBypassText;
        }

        var lines = new List<string>
        {
            "These browsers can send DNS straight to their own DoH provider, past the Axiom " +
            "resolver, so Privacy Shield neither sees nor blocks their queries:",
        };
        foreach (var finding in findings)
        {
            lines.Add($"\u2022 {finding.Application}: {finding.Detail}");
        }

        lines.Add(
            "Turn secure DNS off, then restart the browser: Chrome \u2192 chrome://settings/security, " +
            "Edge \u2192 edge://settings/privacy, Firefox \u2192 Settings \u2192 Privacy & Security \u2192 " +
            "DNS over HTTPS \u2192 Off.");
        return string.Join("\n", lines);
    }

    private static void AddChromium(List<DohBypassFinding> findings, string application, string userDataPath)
    {
        var enabled = new List<string>();
        foreach (var profilePath in EnumerateChromiumProfiles(userDataPath))
        {
            var state = ReadChromiumState(Path.Combine(profilePath, "Preferences"));
            if (state is not null)
            {
                enabled.Add($"{Path.GetFileName(profilePath)} {state}");
            }
        }

        if (enabled.Count > 0)
        {
            findings.Add(new DohBypassFinding(application, string.Join("; ", enabled)));
        }
    }

    private static List<string> EnumerateChromiumProfiles(string userDataPath)
    {
        try
        {
            if (!Directory.Exists(userDataPath))
            {
                return [];
            }

            return Directory
                .GetDirectories(userDataPath)
                .Where(path =>
                {
                    var name = Path.GetFileName(path);
                    return name.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                           name.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase);
                })
                .OrderBy(path => Path.GetFileName(path).Equals("Default", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
                .ThenBy(path => Path.GetFileName(path), StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static string? ReadChromiumState(string preferencesPath)
    {
        try
        {
            if (!File.Exists(preferencesPath))
            {
                return null;
            }

            using var document = JsonDocument.Parse(File.ReadAllBytes(preferencesPath));
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("dns_over_https", out var doh) ||
                doh.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var mode = ReadString(doh, "mode");
            var template = ReadTemplate(doh);
            if (mode.Equals("secure", StringComparison.OrdinalIgnoreCase))
            {
                return template is null
                    ? "uses secure DNS (DoH) through the browser's built-in provider"
                    : $"uses secure DNS (DoH) through {template}";
            }

            // Automatic without a template only upgrades a resolver Chrome already knows; the Axiom
            // loopback address is not one, so it stays on plain DNS and is not reported.
            if (mode.Equals("automatic", StringComparison.OrdinalIgnoreCase) && template is not null)
            {
                return $"uses automatic secure DNS with the custom template {template}";
            }

            return null;
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    private static string ReadString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;

    private static string? ReadTemplate(JsonElement doh)
    {
        if (!doh.TryGetProperty("templates", out var templates))
        {
            return null;
        }

        if (templates.ValueKind == JsonValueKind.String)
        {
            var single = templates.GetString();
            return string.IsNullOrWhiteSpace(single) ? null : single;
        }

        if (templates.ValueKind == JsonValueKind.Array)
        {
            var values = templates
                .EnumerateArray()
                .Where(item => item.ValueKind == JsonValueKind.String)
                .Select(item => item.GetString())
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .ToArray();
            return values.Length == 0 ? null : string.Join(", ", values);
        }

        return null;
    }

    private static void AddFirefox(List<DohBypassFinding> findings, string profilesPath)
    {
        var enabled = new List<string>();
        foreach (var profilePath in EnumerateFirefoxProfiles(profilesPath))
        {
            var state = ReadFirefoxState(Path.Combine(profilePath, "prefs.js"));
            if (state is not null)
            {
                enabled.Add($"{Path.GetFileName(profilePath)} {state}");
            }
        }

        if (enabled.Count > 0)
        {
            findings.Add(new DohBypassFinding("Firefox", string.Join("; ", enabled)));
        }
    }

    private static List<string> EnumerateFirefoxProfiles(string profilesPath)
    {
        try
        {
            if (!Directory.Exists(profilesPath))
            {
                return [];
            }

            return Directory
                .GetDirectories(profilesPath)
                .OrderBy(path => Path.GetFileName(path), StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static string? ReadFirefoxState(string prefsPath)
    {
        try
        {
            if (!File.Exists(prefsPath))
            {
                return null;
            }

            var prefs = File.ReadAllText(prefsPath);
            var modeMatch = TrrModePattern.Match(prefs);
            if (!modeMatch.Success || !int.TryParse(modeMatch.Groups[1].Value, out var mode))
            {
                return null;
            }

            // 2 = DoH first with plain-DNS fallback, 3 = DoH only. Both leave the Axiom resolver.
            if (mode is not (2 or 3))
            {
                return null;
            }

            var uri = TrrUriPattern.Match(prefs) is { Success: true } uriMatch
                ? uriMatch.Groups[1].Value
                : null;
            var scope = mode == 3
                ? "uses DNS over HTTPS only (network.trr.mode 3)"
                : "uses DNS over HTTPS first with a plain-DNS fallback (network.trr.mode 2)";
            return string.IsNullOrWhiteSpace(uri) ? scope : $"{scope} through {uri}";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
