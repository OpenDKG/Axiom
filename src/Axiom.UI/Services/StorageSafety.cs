// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace Axiom.UI.Services;

/// <summary>Read-only filesystem safety checks used before an explicitly approved agent-hook write.</summary>
public static class StorageSafety
{
    public static bool IsReparsePoint(string path)
    {
        try
        {
            return File.Exists(path) || Directory.Exists(path)
                ? (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0
                : false;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return true;
        }
    }

    /// <summary>
    /// Returns true when the path itself or any existing parent is a junction or symbolic link.
    /// This prevents installers and cleanup scripts from following a user-created link into data
    /// outside the Axiom-owned directory.
    /// </summary>
    public static bool IsReparsePointInPath(string path)
    {
        try
        {
            var current = Path.GetFullPath(path);
            while (!string.IsNullOrEmpty(current))
            {
                if ((File.Exists(current) || Directory.Exists(current)) &&
                    (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                {
                    return true;
                }

                var parent = Path.GetDirectoryName(current);
                if (string.IsNullOrEmpty(parent) ||
                    string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }

                current = parent;
            }

            return false;
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return true;
        }
    }

    public static string? BackupFile(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            var directory = Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(directory))
            {
                return null;
            }

            var backup = Path.Combine(
                directory,
                $"{Path.GetFileName(path)}.axiom-backup-{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}");
            File.Copy(path, backup, overwrite: false);
            return backup;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
