// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;

namespace Axiom.Desktop.Avalonia.Linux;

/// <summary>
/// Appends host diagnostics to <c>$XDG_STATE_HOME/axiom/desktop.log</c> (default
/// <c>~/.local/state/axiom/desktop.log</c>). Never logs secrets: only exception text and fixed host
/// messages are written. Also echoed to stderr so a terminal launch with output redirection
/// captures the same lines.
/// </summary>
internal static class StartupLog
{
    private static readonly object Gate = new();

    public static string LogPath => Path.Combine(LinuxPaths.StateDirectory, "desktop.log");

    public static void Write(string category, string message)
    {
        var line = string.Create(
            CultureInfo.InvariantCulture,
            $"{DateTimeOffset.UtcNow:O} [{category}] {message}");
        lock (Gate)
        {
            try
            {
                Console.Error.WriteLine(line);
                var directory = Path.GetDirectoryName(LogPath)!;
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                    File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                }

                var info = new FileInfo(LogPath);
                if (info.Exists && info.Length > 1_000_000)
                {
                    File.Move(LogPath, LogPath + ".1", overwrite: true);
                }

                File.AppendAllText(LogPath, line + Environment.NewLine);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }
    }

    public static void Write(string category, Exception exception) =>
        Write(category, exception.ToString());
}
