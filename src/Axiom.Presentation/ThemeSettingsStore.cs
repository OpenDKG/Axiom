// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace Axiom.Presentation;

/// <summary>
/// Stores the selected palette in a tiny per-user file containing only the word Dark or Light.
/// No paths, accounts or telemetry are written.
/// </summary>
public static class ThemeSettingsStore
{
    private static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "theme.txt");

    /// <summary>True once the user has picked a palette (hosts may follow the OS until then).</summary>
    public static bool HasSavedTheme
    {
        get
        {
            try
            {
                return File.Exists(SettingsPath);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return false;
            }
        }
    }

    public static UiTheme Load()
    {
        try
        {
            if (!File.Exists(SettingsPath))
            {
                return UiTheme.Dark;
            }

            var value = File.ReadAllText(SettingsPath).Trim();
            return Enum.TryParse<UiTheme>(value, ignoreCase: true, out var theme)
                ? theme
                : UiTheme.Dark;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return UiTheme.Dark;
        }
    }

    public static void Save(UiTheme theme)
    {
        try
        {
            var directory = Path.GetDirectoryName(SettingsPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(SettingsPath, theme.ToString());
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A read-only profile must not prevent this session from switching theme.
        }
    }
}
