// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;

namespace Axiom.Infrastructure.MacOS.Filter;

/// <summary>
/// Atomic publication of rules.json: write a temp file in the same directory, flush it to disk,
/// set mode 0644 and rename over the target. The filter therefore sees either the old or the new
/// complete table, never a partial file.
/// </summary>
public static class FilterRulesFile
{
    public const UnixFileMode PublishedMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    public static void WriteAtomic(string path, string content)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(content);

        var directory = Path.GetDirectoryName(Path.GetFullPath(path))
                        ?? throw new ArgumentException("Path has no directory.", nameof(path));
        Directory.CreateDirectory(directory);

        var temp = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            var bytes = Encoding.UTF8.GetBytes(content);
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(temp, PublishedMode);
            }

            // rename(2) on Unix: atomic replacement within one file system.
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
        }
    }

    public static void WriteAtomic(string path, FilterRuleTable table)
    {
        ArgumentNullException.ThrowIfNull(table);
        WriteAtomic(path, table.ToJson() + "\n");
    }

    /// <summary>Reads the current table; null when missing or invalid.</summary>
    public static FilterRuleTable? TryRead(string path)
    {
        try
        {
            return File.Exists(path) ? FilterRuleTable.TryParse(File.ReadAllText(path)) : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
