// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Axiom.Presentation;

/// <summary>
/// Reads the Complete-installation consent that lets Axiom turn on signed, redacted threat sharing
/// once, and remembers that it already did so. A user who later turns sharing off is not overridden.
/// </summary>
public static class ThreatSharingConsent
{
    public static string DefaultProfilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "install-profile.json");

    public static string DefaultAppliedPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "threat-sharing-consent-applied");

    /// <summary>
    /// Only the Windows installer records an install-time consent. Off Windows nothing writes the
    /// profile, so a file at the default path (restored backup, synced home) is not a consent the
    /// user gave on this machine: threat sharing stays a manual switch there.
    /// </summary>
    public static bool IsInstallConsentSupported => OperatingSystem.IsWindows();

    /// <summary>True when the installer recorded the Complete threat-sharing consent.</summary>
    public static bool HasConsent(string? profilePath = null)
    {
        if (profilePath is null && !IsInstallConsentSupported)
        {
            return false;
        }

        var path = profilePath ?? DefaultProfilePath;
        try
        {
            if (!File.Exists(path))
            {
                return false;
            }

            var root = JsonNode.Parse(File.ReadAllText(path)) as JsonObject;
            return root?["threatSharingConsent"]?.GetValue<bool>() == true;
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or FormatException)
        {
            return false;
        }
    }

    public static bool WasApplied(string? appliedPath = null) =>
        File.Exists(appliedPath ?? DefaultAppliedPath);

    public static void MarkApplied(string? appliedPath = null)
    {
        var path = appliedPath ?? DefaultAppliedPath;
        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(path, DateTimeOffset.UtcNow.ToString("O"));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Losing the marker only means the next start may try once more; it never blocks the app.
        }
    }
}
