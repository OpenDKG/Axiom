// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace Axiom.Contracts;

/// <summary>Operating system families that have their own data-root conventions.</summary>
public enum AxiomPlatform
{
    Windows = 0,
    MacOS = 1,
    Linux = 2,
}

/// <summary>
/// Single source of truth for Axiom's machine-wide and per-user data roots and for deciding
/// whether the current process is the background service. Windows results are identical to the
/// historical <c>%ProgramData%\Axiom</c> / <c>%LocalAppData%\Axiom</c> and
/// <c>!Environment.UserInteractive</c> logic; Unix needs its own rules because
/// <see cref="Environment.SpecialFolder.CommonApplicationData"/> is <c>/usr/share</c> there and
/// <see cref="Environment.UserInteractive"/> is always true.
/// </summary>
public static class AxiomPaths
{
    public const string DirectoryName = "Axiom";

    /// <summary>Data directory name on Linux (<c>/var/lib/axiom</c>).</summary>
    public const string LinuxDirectoryName = "axiom";

    /// <summary>Overrides the data directory of the database and Privacy Shield files.</summary>
    public const string DataDirectoryVariable = "AXIOM_DATA_DIR";

    /// <summary>Set to <c>1</c> by the launchd plist so the daemon knows it is the service.</summary>
    public const string ServiceVariable = "AXIOM_SERVICE";

    public const string MacMachineBase = "/Library/Application Support";

    public const string LinuxMachineBase = "/var/lib";

    public static AxiomPlatform CurrentPlatform =>
        OperatingSystem.IsWindows() ? AxiomPlatform.Windows
        : OperatingSystem.IsMacOS() ? AxiomPlatform.MacOS
        : AxiomPlatform.Linux;

    /// <summary>
    /// Parent directory of the machine data directory: <c>%ProgramData%</c> on Windows,
    /// <c>/Library/Application Support</c> on macOS and <c>/var/lib</c> on Linux.
    /// </summary>
    public static string MachineBaseDirectory => MachineBaseDirectoryFor(
        CurrentPlatform,
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));

    /// <summary>Machine-wide data directory (service database, shield, privacy, filter state).</summary>
    public static string MachineDataDirectory => MachineDataDirectoryFor(
        CurrentPlatform,
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));

    /// <summary>Parent directory of the per-user data directory (LocalApplicationData).</summary>
    public static string UserBaseDirectory =>
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    /// <summary>Per-user data directory (<c>~/Library/Application Support/Axiom</c> on macOS).</summary>
    public static string UserDataDirectory => Path.Combine(UserBaseDirectory, DirectoryName);

    /// <summary>
    /// True for the installed background service: a non-interactive process on Windows; on Unix a
    /// process started with <c>AXIOM_SERVICE=1</c> or running with effective uid 0.
    /// </summary>
    public static bool IsServiceProcess => IsServiceProcessFor(
        CurrentPlatform,
        Environment.UserInteractive,
        Environment.GetEnvironmentVariable(ServiceVariable),
        CurrentPlatform == AxiomPlatform.Windows ? uint.MaxValue : SafeGetEffectiveUserId());

    /// <summary>Data directory for the current process: machine for the service, user otherwise.</summary>
    public static string ProcessDataDirectory => IsServiceProcess ? MachineDataDirectory : UserDataDirectory;

    public static string MachineBaseDirectoryFor(AxiomPlatform platform, string? commonApplicationData) =>
        platform switch
        {
            AxiomPlatform.Windows => commonApplicationData ?? string.Empty,
            AxiomPlatform.MacOS => MacMachineBase,
            _ => LinuxMachineBase,
        };

    public static string MachineDataDirectoryFor(AxiomPlatform platform, string? commonApplicationData) =>
        Path.Combine(
            MachineBaseDirectoryFor(platform, commonApplicationData),
            platform == AxiomPlatform.Linux ? LinuxDirectoryName : DirectoryName);

    /// <summary>Pure service-mode decision so every platform rule is unit-testable.</summary>
    public static bool IsServiceProcessFor(
        AxiomPlatform platform,
        bool userInteractive,
        string? serviceVariable,
        uint effectiveUserId)
    {
        if (platform == AxiomPlatform.Windows)
        {
            return !userInteractive;
        }

        return string.Equals(serviceVariable?.Trim(), "1", StringComparison.Ordinal) ||
               effectiveUserId == 0;
    }

    private static uint SafeGetEffectiveUserId()
    {
        try
        {
            return NativeMethods.geteuid();
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException)
        {
            return uint.MaxValue;
        }
    }

    private static class NativeMethods
    {
        [DllImport("libc", EntryPoint = "geteuid")]
        internal static extern uint geteuid();
    }
}
