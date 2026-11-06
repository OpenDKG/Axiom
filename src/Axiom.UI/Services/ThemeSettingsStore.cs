// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace Axiom.UI.Services;

/// <summary>
/// Stores the selected palette in a tiny per-user file. The file contains only the word Dark or
/// Light; no paths, accounts or telemetry are written.
/// </summary>
public static class ThemeSettingsStore
{
    private static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "theme.txt");

    public static AppTheme Load()
    {
        try
        {
            if (!File.Exists(SettingsPath))
            {
                return AppTheme.Dark;
            }

            var value = File.ReadAllText(SettingsPath).Trim();
            return Enum.TryParse<AppTheme>(value, ignoreCase: true, out var theme)
                ? theme
                : AppTheme.Dark;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return AppTheme.Dark;
        }
    }

    public static void Save(AppTheme theme)
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
            // A read-only profile must not prevent the app from switching theme for this session.
        }
    }
}
