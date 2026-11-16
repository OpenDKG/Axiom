// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace Axiom.Presentation;

/// <summary>
/// Stores the chosen shell complexity mode (<see cref="UiMode.Simple"/> or
/// <see cref="UiMode.Advanced"/>) in a small per-user text file. Defaults to Simple for everyday
/// users on first launch.
/// </summary>
public static class UiModeSettingsStore
{
    private static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "ui-mode.txt");

    public static UiMode Load(string? path = null)
    {
        var target = string.IsNullOrWhiteSpace(path) ? DefaultPath : path;
        try
        {
            if (!File.Exists(target))
            {
                return UiMode.Simple;
            }

            var value = File.ReadAllText(target).Trim();
            return Enum.TryParse<UiMode>(value, ignoreCase: true, out var mode)
                ? mode
                : UiMode.Simple;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return UiMode.Simple;
        }
    }

    public static void Save(UiMode mode, string? path = null)
    {
        var target = string.IsNullOrWhiteSpace(path) ? DefaultPath : path;
        try
        {
            var directory = Path.GetDirectoryName(target);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(target, mode.ToString());
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A read-only profile must not block switching modes for the current session.
        }
    }
}
