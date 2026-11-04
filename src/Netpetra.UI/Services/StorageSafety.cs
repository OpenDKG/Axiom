// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace Netpetra.UI.Services;

/// <summary>Filesystem safety checks used before an explicitly approved agent-hook write.</summary>
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
            // If the location cannot be inspected, never write through it.
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
                $"{Path.GetFileName(path)}.netpetra-backup-{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}");
            File.Copy(path, backup, overwrite: false);
            return backup;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
