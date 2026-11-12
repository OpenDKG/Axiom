// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;

namespace Axiom.Infrastructure.MacOS.Filter;

/// <summary>
/// Atomic publication of daemon files: write a temp file in the same directory, flush it to
/// disk, set the mode and rename over the target. A reader therefore sees either the old or the
/// new complete file, never a partial one. rules.json is published 0644 (the AxiomFilter
/// extension reads it); every other daemon file is 0600 (<see cref="PrivateMode"/>).
/// </summary>
public static class FilterRulesFile
{
    /// <summary>0644: the rule table read by the filter extension.</summary>
    public const UnixFileMode PublishedMode = MacDataDirectoryPermissions.SharedFileMode;

    /// <summary>0600: daemon-private state (managed rules, DNS backup).</summary>
    public const UnixFileMode PrivateMode = MacDataDirectoryPermissions.PrivateFileMode;

    public static void WriteAtomic(string path, string content) => WriteAtomic(path, content, PublishedMode);

    public static void WriteAtomic(string path, string content, UnixFileMode mode)
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
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = mode;
            }

            using (var stream = new FileStream(temp, options))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            if (!OperatingSystem.IsWindows())
            {
                // UnixCreateMode is subject to the umask; set the exact mode.
                File.SetUnixFileMode(temp, mode);
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
        WriteAtomic(path, table.ToJson() + "\n", PublishedMode);
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
