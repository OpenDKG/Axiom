// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;

namespace Axiom.Desktop.Avalonia.Linux;

/// <summary>
/// Decides whether to create the tray icon. Avalonia's Linux tray is a StatusNotifierItem over the
/// session bus; it only shows when a StatusNotifierWatcher is registered (KDE Plasma natively,
/// GNOME with the AppIndicator extension). Stock GNOME has none, and then Axiom must not hide its
/// window to a tray that does not exist: closing the window quits.
/// </summary>
public static class StatusNotifierProbe
{
    public const string WatcherName = "org.kde.StatusNotifierWatcher";

    /// <summary><c>AXIOM_TRAY=0</c> disables the tray even with a watcher, <c>1</c> forces the attempt.</summary>
    public const string OverrideVariable = "AXIOM_TRAY";

    /// <summary>Pure decision: the override wins, else the watcher must be present.</summary>
    public static bool ShouldCreateTray(bool watcherPresent, string? overrideValue) =>
        overrideValue?.Trim() switch
        {
            "0" or "false" or "no" => false,
            "1" or "true" or "yes" => true,
            _ => watcherPresent,
        };

    /// <summary>Parses <c>dbus-send --print-reply</c> output of <c>NameHasOwner</c>.</summary>
    public static bool ParseNameHasOwner(string output) =>
        output.Contains("boolean true", StringComparison.Ordinal);

    public static bool IsWatcherPresent()
    {
        try
        {
            var startInfo = new ProcessStartInfo("/usr/bin/dbus-send")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            foreach (var argument in new[]
                     {
                         "--session", "--print-reply", "--dest=org.freedesktop.DBus", "/org/freedesktop/DBus",
                         "org.freedesktop.DBus.NameHasOwner", "string:" + WatcherName,
                     })
            {
                startInfo.ArgumentList.Add(argument);
            }

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return false;
            }

            var output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(3000))
            {
                process.Kill();
                return false;
            }

            return process.ExitCode == 0 && ParseNameHasOwner(output);
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return false;
        }
    }
}
