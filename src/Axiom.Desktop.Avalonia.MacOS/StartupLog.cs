// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Contracts;

namespace Axiom.Desktop.Avalonia.MacOS;

/// <summary>
/// Appends host diagnostics to <c>~/Library/Application Support/Axiom/desktop.log</c>. Never logs
/// secrets: only exception text and fixed host messages are written. Also echoed to stderr so a
/// Terminal launch with output redirection captures the same lines.
/// </summary>
internal static class StartupLog
{
    private static readonly object Gate = new();

    public static string LogPath => Path.Combine(AxiomPaths.UserDataDirectory, "desktop.log");

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
                Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
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
