// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Infrastructure.MacOS.Interop;

namespace Axiom.Infrastructure.MacOS.Launchd;

/// <summary>
/// Where the root daemon lives and what the copy must look like. launchd trusts the plist owner,
/// not the program, so a daemon that runs from the user-writable <c>Axiom.app</c> bundle could be
/// replaced by any process of that user. <c>--install-service</c> therefore copies the published
/// daemon into <c>/Library/PrivilegedHelperTools/com.axiom.service</c> (root:wheel, 0755 dirs,
/// 0644 files, 0755 executables) and refuses to bootstrap unless <see cref="Audit"/> passes.
/// </summary>
public static class PrivilegedHelperLayout
{
    public const string HelperRoot = "/Library/PrivilegedHelperTools";

    public const string HelperDirectory = HelperRoot + "/" + MacServicePaths.LaunchdLabel;

    public const string DaemonFileName = "axiomd";

    public const UnixFileMode DirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
        UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherExecute;

    public const UnixFileMode ExecutableMode = DirectoryMode;

    public const UnixFileMode FileMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    public const UnixFileMode AnyExecute = UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;

    /// <summary>Daemon path inside the helper directory.</summary>
    public static string DaemonPath => Path.Combine(HelperDirectory, DaemonFileName);

    /// <summary>Mode a copied entry gets: directories and anything executable 0755, data 0644.</summary>
    public static UnixFileMode ModeFor(bool isDirectory, UnixFileMode sourceMode) =>
        isDirectory || (sourceMode & AnyExecute) != 0 ? ExecutableMode : FileMode;

    /// <summary>
    /// Pure check of a file listing: every entry must be uid 0 and neither group- nor
    /// world-writable, the directory and the daemon must be present, and the daemon executable.
    /// Returns the problems found (empty = pass).
    /// </summary>
    public static IReadOnlyList<string> Audit(string helperDirectory, IReadOnlyList<UnixFileEntry> entries)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(helperDirectory);
        ArgumentNullException.ThrowIfNull(entries);

        var problems = new List<string>();
        var daemonPath = Path.Combine(helperDirectory, DaemonFileName);
        var directory = entries.FirstOrDefault(entry => entry.Path == helperDirectory);
        if (directory is null)
        {
            problems.Add($"{helperDirectory} is missing from the listing.");
        }
        else if (!directory.IsDirectory)
        {
            problems.Add($"{helperDirectory} is not a directory.");
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
}
