// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.MacOS;

/// <summary>
/// Modes of the daemon log (<c>/Library/Logs/Axiom</c>): the directory is root-only 0700, the
/// log and every rotated archive (<c>axiomd.log.0.bz2</c>, …) are 0600 (review 2026-11-12,
/// Medium #5). The log carries process names, paths and rule ids of every local user, so a
/// second standard account must not read it. launchd creates <c>StandardOutPath</c> with the
/// default umask (0644) when the file is missing, which is why the installer pre-creates it and
/// the daemon re-applies the modes at every start and newsyslog is told to rotate with 600.
/// </summary>
public static class MacLogPermissions
{
    /// <summary>0700.</summary>
    public const UnixFileMode DirectoryMode = MacDataDirectoryPermissions.PrivateDirectoryMode;

    /// <summary>0600.</summary>
    public const UnixFileMode FileMode = MacDataDirectoryPermissions.PrivateFileMode;

    /// <summary>The newsyslog <c>mode</c> column for the daemon log.</summary>
    public const string NewsyslogMode = "600";

    /// <summary>
    /// Creates <paramref name="logDirectory"/> (0700) and <paramref name="logFilePath"/> (0600,
    /// empty) when missing and sets the directory, the log and its rotated archives to the
    /// private modes. Returns the paths whose mode changed. Never throws for a single entry.
    /// </summary>
    public static IReadOnlyList<string> Enforce(string logDirectory, string logFilePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(logFilePath);

        var changed = new List<string>();
        Directory.CreateDirectory(logDirectory);
        if (OperatingSystem.IsWindows())
        {
            return changed; // Unix modes only; the type lives in the macOS assembly but builds everywhere.
        }

        Apply(logDirectory, DirectoryMode, changed);

        if (!File.Exists(logFilePath))
        {
            using (new FileStream(logFilePath, new FileStreamOptions
            {
                Mode = System.IO.FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.ReadWrite,
                UnixCreateMode = FileMode,
            }))
            {
            }

            changed.Add(logFilePath);
        }

        foreach (var file in Archives(logDirectory, logFilePath))
        {
            Apply(file, FileMode, changed);
        }

        return changed;
    }

    /// <summary>The log and every rotated archive next to it (<c>name.N</c>, <c>name.N.bz2</c>, …).</summary>
    public static IEnumerable<string> Archives(string logDirectory, string logFilePath)
    {
        var name = Path.GetFileName(logFilePath);
        if (!Directory.Exists(logDirectory))
        {
            return [];
        }

        return Directory.EnumerateFiles(logDirectory)
            .Where(file => string.Equals(Path.GetFileName(file), name, StringComparison.Ordinal) ||
                           Path.GetFileName(file).StartsWith(name + ".", StringComparison.Ordinal))
            .OrderBy(file => file, StringComparer.Ordinal);
    }

    private static void Apply(string path, UnixFileMode mode, List<string> changed)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            if (File.GetUnixFileMode(path) == mode)
            {
                return;
            }

            File.SetUnixFileMode(path, mode);
            changed.Add(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The caller reports; a single unreadable entry must not stop the daemon.
        }
    }
}
