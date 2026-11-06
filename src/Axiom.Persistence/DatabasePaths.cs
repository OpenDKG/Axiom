// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;
using Axiom.Contracts.Ipc;

namespace Axiom.Persistence;

/// <summary>Default on-disk locations.</summary>
public static class DatabasePaths
{
    public const string DataDirectoryName = "Axiom";

    public const string DatabaseFileName = "axiom.db";

    /// <summary>Installation path used by the service installer (FND-009).</summary>
    public static string DefaultDatabasePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        DataDirectoryName,
        DatabaseFileName);

    /// <summary>
    /// Console development and per-user runs write under LocalAppData; an installed service
    /// (non-interactive) uses ProgramData. AXIOM_DATA_DIR overrides both. On Unix a root service
    /// uses <c>/var/lib/axiom</c> and an unprivileged process uses the XDG data directory.
    /// </summary>
    public static string ResolveDataDirectory()
    {
        var configured = Environment.GetEnvironmentVariable("AXIOM_DATA_DIR")
                         ?? Environment.GetEnvironmentVariable(LegacyIdentity.ProductName + "_DATA_DIR");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        if (!OperatingSystem.IsWindows())
        {
            if (PosixIdentity.IsSuperUser)
            {
                return "/var/lib/axiom";
            }

            var xdg = Environment.GetEnvironmentVariable("XDG_DATA_HOME");
            var root = string.IsNullOrWhiteSpace(xdg)
                ? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    DataDirectoryName)
                : Path.Combine(xdg, DataDirectoryName);

            return root;
        }

        var windowsRoot = Environment.UserInteractive
            ? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            : Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        return Path.Combine(windowsRoot, DataDirectoryName);
    }

    public static string ResolveForCurrentProcess() =>
        Path.Combine(ResolveDataDirectory(), DatabaseFileName);

    /// <summary>
    /// Privacy Shield files keep their historical Windows per-user location. Moving an installed
    /// service from LocalApplicationData to ProgramData would silently abandon existing settings
    /// and compiled rules, so only the Unix path follows the platform data directory.
    /// </summary>
    public static string ResolvePrivacyShieldDirectory() =>
        OperatingSystem.IsWindows()
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                DataDirectoryName)
            : ResolveDataDirectory();

    /// <summary>
    /// Creates a data directory only its owner can read. Connection history and settings are user
    /// data; the process umask must not make them world-readable on a multi-user host. Existing
    /// directories are never chmod-ed in place when they contain data: an operator who pointed
    /// AXIOM_DATA_DIR at a shared directory gets an error instead of a broken host directory.
    /// </summary>
    public static string EnsurePrivateDirectory(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(directory);
            return directory;
        }

        const UnixFileMode privateMode =
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

        if (!Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
            File.SetUnixFileMode(directory, privateMode);
            return directory;
        }

        // Mode 0700 is not privacy if another uid owns the directory. A root service pointed at a
        // user-owned directory would let that user read or replace all-account history.
        if (!PosixIdentity.TryGetOwnerUserId(directory, out var owner))
        {
            throw new PlatformNotSupportedException(
                $"Cannot verify the owner of data directory '{directory}' on this platform.");
        }

        if (owner != PosixIdentity.EffectiveUserId)
        {
            throw new UnauthorizedAccessException(
                $"Refusing to store Axiom data in '{directory}': it is owned by uid {owner}, " +
                $"not the service uid {PosixIdentity.EffectiveUserId}.");
        }

        var mode = File.GetUnixFileMode(directory);
        const UnixFileMode nonPrivateBits =
            UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

        if ((mode & nonPrivateBits) != 0)
        {
            if (Directory.EnumerateFileSystemEntries(directory).Any())
            {
                throw new UnauthorizedAccessException(
                    $"Refusing to store Axiom data in '{directory}': the existing directory is not " +
                    "private and contains files. Use a dedicated directory or chmod it 0700.");
            }

            File.SetUnixFileMode(directory, privateMode);
        }

        return directory;
    }
}
