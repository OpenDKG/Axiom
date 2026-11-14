// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.RegularExpressions;

namespace Axiom.Presentation;

/// <summary>
/// Adjusts the one plugin setting a full install needs on a slow or antivirus-scanned machine.
///
/// Hermes gives a plugin ten seconds to import and register. The Blackbox plugin imports the DKG
/// client, the curator and the dashboard, which on a cold disk regularly takes longer than that, so
/// the plugin is skipped with "load timed out" and its <c>hermes blackbox</c> command never exists —
/// the Share button then has no reporter to call. The value is the vendor's own config key
/// (<c>plugins.load_timeout_seconds</c>, clamped to 600), written line-by-line so comments and every
/// unrelated key survive.
/// </summary>
public static class HermesPluginSettings
{
    public const int DefaultLoadTimeoutSeconds = 120;

    public const int MinimumLoadTimeoutSeconds = 10;

    public const int MaximumLoadTimeoutSeconds = 600;

    /// <summary>Sets <c>plugins.load_timeout_seconds</c>, preserving the rest of the file.</summary>
    public static string ApplyLoadTimeout(string yaml, int seconds = DefaultLoadTimeoutSeconds)
    {
        var value = Math.Clamp(seconds, MinimumLoadTimeoutSeconds, MaximumLoadTimeoutSeconds);
        var text = (yaml ?? string.Empty).Replace("\r\n", "\n");
        if (text.Length == 0)
        {
            return $"plugins:\n  load_timeout_seconds: {value}\n";
        }

        var lines = text.Split('\n').ToList();
        var pluginsIndex = lines.FindIndex(line =>
            Regex.IsMatch(line, @"^plugins:\s*(#.*)?$"));
        if (pluginsIndex < 0)
        {
            return $"plugins:\n  load_timeout_seconds: {value}\n" + text;
        }

        // The key belongs to the top-level plugins block: stop at the next unindented key.
        var end = lines.Count;
        for (var index = pluginsIndex + 1; index < lines.Count; index++)
        {
            var line = lines[index];
            if (line.Length > 0 && !char.IsWhiteSpace(line[0]) && !line.StartsWith('#'))
            {
                end = index;
                break;
            }
        }

        for (var index = pluginsIndex + 1; index < end; index++)
        {
            var match = Regex.Match(lines[index], @"^(\s+)load_timeout_seconds:\s*\d+\s*(#.*)?$");
            if (match.Success)
            {
                var comment = match.Groups[2].Success ? " " + match.Groups[2].Value : string.Empty;
                lines[index] = $"{match.Groups[1].Value}load_timeout_seconds: {value}{comment}";
                return string.Join("\n", lines);
            }
        }

        lines.Insert(pluginsIndex + 1, $"  load_timeout_seconds: {value}");
        return string.Join("\n", lines);
    }

    /// <summary>True when the config asks for at least <paramref name="minimum"/> seconds.</summary>
    public static bool HasLoadTimeout(string? yaml, int minimum = 60)
    {
        if (string.IsNullOrEmpty(yaml))
        {
            return false;
        }

        var match = Regex.Match(yaml, @"(?m)^\s+load_timeout_seconds:\s*(\d+)\s*$");
        return match.Success &&
               int.TryParse(match.Groups[1].Value, out var seconds) &&
               seconds >= minimum;
    }

    /// <summary>Applies the setting to an existing config; a missing file is left to the vendor installer.</summary>
    public static bool ApplyToFile(string configPath, int seconds = DefaultLoadTimeoutSeconds)
    {
        try
        {
            if (StorageSafety.IsReparsePointInPath(configPath) || !File.Exists(configPath))
            {
                return false;
            }

            var text = File.ReadAllText(configPath);
            var updated = ApplyLoadTimeout(text, seconds);
            if (string.Equals(text, updated, StringComparison.Ordinal))
            {
                return true;
            }

            StorageSafety.BackupFile(configPath);
            File.WriteAllText(configPath, updated);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
