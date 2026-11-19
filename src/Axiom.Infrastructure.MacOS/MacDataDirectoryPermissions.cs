// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.MacOS;

/// <summary>
/// Modes of the machine data directory (<c>/Library/Application Support/Axiom</c>). The root
/// daemon is the only writer; other local users must not read history, settings or the DNS
/// backup. The data root is 0700; <c>filter/</c> is 0755 with <c>rules.json</c> 0644 (the
/// AxiomFilter extension reads it; everything else there is daemon state, 0600). Applied at
/// daemon start (<see cref="Enforce"/>, idempotent) and by every store at write time.
/// </summary>
public static class MacDataDirectoryPermissions
{
    public const string FilterDirectoryName = "filter";

    public const string RulesFileName = "rules.json";

    /// <summary>0700.</summary>
    public const UnixFileMode PrivateDirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    /// <summary>0755.</summary>
    public const UnixFileMode SharedDirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
        UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherExecute;

    /// <summary>0600.</summary>
    public const UnixFileMode PrivateFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    /// <summary>0644.</summary>
    public const UnixFileMode SharedFileMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    /// <summary>Expected mode of <paramref name="path"/> below <paramref name="root"/> (pure).</summary>
    public static UnixFileMode ExpectedMode(string root, string path, bool isDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var filterDirectory = Path.Combine(root, FilterDirectoryName);
        if (isDirectory)
        {
            return path == filterDirectory ? SharedDirectoryMode : PrivateDirectoryMode;
        }

        return path == Path.Combine(filterDirectory, RulesFileName) ? SharedFileMode : PrivateFileMode;
    }

    /// <summary>
    /// Creates the root and <c>filter/</c> directories and sets every existing entry to its
    /// expected mode. Returns the paths whose mode was changed. Never throws for a single
    /// unreadable entry; the caller logs the result.
    /// </summary>
    public static IReadOnlyList<string> Enforce(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);

        var changed = new List<string>();
        Directory.CreateDirectory(Path.Combine(root, FilterDirectoryName));
        foreach (var directory in new[] { root, Path.Combine(root, FilterDirectoryName) })
        {
            Apply(root, directory, isDirectory: true, changed);
        }

        foreach (var entry in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories))
        {
            if (entry == Path.Combine(root, FilterDirectoryName))
            {
                continue;
            }

            Apply(root, entry, Directory.Exists(entry), changed);
        }

        return changed;
    }

    /// <summary>Sets a freshly written daemon file to 0600 (no-op on Windows).</summary>
    public static void SetPrivate(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, PrivateFileMode);
        }
    }

    private static void Apply(string root, string path, bool isDirectory, List<string> changed)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            var expected = ExpectedMode(root, path, isDirectory);
            if (File.GetUnixFileMode(path) != expected)
            {
                File.SetUnixFileMode(path, expected);
                changed.Add(path);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A socket or a vanished temp file; the next start retries.
        }
    }
}
