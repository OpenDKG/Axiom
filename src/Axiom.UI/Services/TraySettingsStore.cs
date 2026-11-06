// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace Axiom.UI.Services;

/// <summary>Opt-out for Windows shell notifications, independent of the visible tray status icon.</summary>
public static class TraySettingsStore
{
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "tray-notifications.txt");

    public static bool Enabled { get; private set; } = Load();

    public static event EventHandler? Changed;

    public static void SetEnabled(bool enabled)
    {
        if (Enabled == enabled)
        {
            return;
        }

        Enabled = enabled;
        try
        {
            var directory = Path.GetDirectoryName(SettingsPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(SettingsPath, enabled ? "enabled" : "disabled");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A restricted user profile should not crash the tray or the Settings view.
        }

        Changed?.Invoke(null, EventArgs.Empty);
    }

    private static bool Load()
    {
        try
        {
            if (!File.Exists(SettingsPath))
            {
                return true;
            }

            return !string.Equals(File.ReadAllText(SettingsPath).Trim(),
                "disabled", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return true;
        }
    }
}
