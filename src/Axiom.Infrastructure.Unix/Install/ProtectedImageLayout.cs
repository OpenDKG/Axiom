// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Unix.Install;

/// <summary>
/// What the root-owned copy of the daemon must look like, on any Unix. The init system trusts the
/// job definition's owner, not the program, so a daemon that runs from a user-writable location
/// could be replaced by any process of that user. <c>--install-service</c> therefore copies the
/// published daemon into a root-owned directory (<c>/Library/PrivilegedHelperTools/com.axiom.service</c>
/// on macOS, <c>/usr/libexec/axiom</c> on Linux; 0755 dirs, 0644 files, 0755 executables) and
/// refuses to start it unless <see cref="Audit"/> passes. This is the Unix twin of upstream's
/// Windows <c>ServiceImageProtection</c>.
/// </summary>
public static class ProtectedImageLayout
{
    public const string DaemonFileName = "axiomd";

    public const UnixFileMode DirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
        UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherExecute;

    public const UnixFileMode ExecutableMode = DirectoryMode;

    public const UnixFileMode FileMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    public const UnixFileMode AnyExecute = UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;

    /// <summary>Mode a copied entry gets: directories and anything executable 0755, data 0644.</summary>
    public static UnixFileMode ModeFor(bool isDirectory, UnixFileMode sourceMode) =>
        isDirectory || (sourceMode & AnyExecute) != 0 ? ExecutableMode : FileMode;

    /// <summary>
    /// Pure check of a file listing: every entry must be uid 0 and neither group- nor
    /// world-writable, the directory and the daemon must be present, and the daemon executable.
    /// Returns the problems found (empty = pass).
    /// </summary>
    public static IReadOnlyList<string> Audit(string imageDirectory, IReadOnlyList<UnixFileEntry> entries)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(imageDirectory);
        ArgumentNullException.ThrowIfNull(entries);

        var problems = new List<string>();
        var daemonPath = Path.Combine(imageDirectory, DaemonFileName);
        var directory = entries.FirstOrDefault(entry => entry.Path == imageDirectory);
        if (directory is null)
        {
            problems.Add($"{imageDirectory} is missing from the listing.");
        }
        else if (!directory.IsDirectory)
        {
            problems.Add($"{imageDirectory} is not a directory.");
        }

        var daemon = entries.FirstOrDefault(entry => entry.Path == daemonPath);
        if (daemon is null)
        {
            problems.Add($"{daemonPath} is missing from the listing.");
        }
        else if ((daemon.Permissions & 0x49) == 0)
        {
            problems.Add($"{daemonPath} is not executable ({daemon.Describe()}).");
        }

        foreach (var entry in entries)
        {
            if (!entry.IsRootOwned)
            {
                problems.Add($"{entry.Path} is owned by uid {entry.Uid.ToString(CultureInfo.InvariantCulture)}, not root ({entry.Describe()}).");
            }

            if (entry.IsGroupOrWorldWritable)
            {
                problems.Add($"{entry.Path} is group- or world-writable ({entry.Describe()}).");
            }
        }

        return problems;
    }

    /// <summary>Every path under <paramref name="directory"/> including itself (depth first, sorted).</summary>
    public static IReadOnlyList<string> EnumerateTree(string directory)
    {
        var paths = new List<string> { directory };
        paths.AddRange(Directory
            .EnumerateFileSystemEntries(directory, "*", SearchOption.AllDirectories)
            .Order(StringComparer.Ordinal));
        return paths;
    }

    /// <summary>
    /// Same check as the Windows installer after the copy to Program Files: the installed daemon
    /// must be byte-identical (SHA-256) to the image the administrator prompt ran.
    /// </summary>
    public static bool FilesMatch(string left, string right)
    {
        try
        {
            return string.Equals(Hash(left), Hash(right), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream));
    }
}
