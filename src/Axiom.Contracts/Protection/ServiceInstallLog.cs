// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;

namespace Axiom.Contracts.Protection;

/// <summary>
/// Append-only diagnostics for the elevated service installer. The setup starts that process with
/// <c>runas</c>, so its stderr cannot be redirected; without this file a failed registration only
/// surfaced as an unexplained exit code (issue #367).
/// </summary>
public static class ServiceInstallLog
{
    private const long MaxBytes = 256 * 1024;

    private const int KeptLines = 200;

    public static string Path => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Axiom",
        "logs",
        "service-install.log");

    public static void Write(string message)
    {
        try
        {
            var path = Path;
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
            if (File.Exists(path) && new FileInfo(path).Length > MaxBytes)
            {
                File.WriteAllLines(path, Tail(KeptLines).Append(message), Encoding.UTF8);
                return;
            }

            File.AppendAllText(
                path,
                $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss} {message}{Environment.NewLine}",
                Encoding.UTF8);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Diagnostics must never decide whether an install succeeds.
        }
    }

    /// <summary>Last <paramref name="maxLines"/> lines, oldest first; empty when nothing was written.</summary>
    public static string[] Tail(int maxLines, string? path = null)
    {
        if (maxLines <= 0)
        {
            return [];
        }

        var target = path ?? Path;
        try
        {
            if (!File.Exists(target))
            {
                return [];
            }

            using var stream = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            var lines = new Queue<string>(maxLines);
            while (reader.ReadLine() is { } line)
            {
                if (lines.Count == maxLines)
                {
                    lines.Dequeue();
                }

                lines.Enqueue(line);
            }

            return [.. lines];
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
