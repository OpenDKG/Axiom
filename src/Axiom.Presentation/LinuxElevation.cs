// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;

namespace Axiom.Presentation;

/// <summary>Outcome of a <c>pkexec</c> run. polkit exits 126 when the dialog is dismissed and 127 when authorization fails.</summary>
public sealed record LinuxElevationResult(int ExitCode, string StandardOutput, string StandardError)
{
    public const int DismissedExitCode = 126;
    public const int NotAuthorizedExitCode = 127;

    public bool Cancelled => ExitCode is DismissedExitCode or NotAuthorizedExitCode;

    public bool Succeeded => ExitCode == 0;
}

/// <summary>
/// Runs one root command through <c>pkexec</c>. polkit shows the desktop's authentication agent
/// (GNOME Shell, KDE, lxpolkit); with <c>packaging/linux/com.axiom.firewall.policy</c> installed in
/// <c>/usr/share/polkit-1/actions</c> the dialog names Axiom and keeps the authorization for a few
/// minutes (<c>auth_admin_keep</c>); without it pkexec still prompts with its generic dialog.
/// The desktop process itself never runs as root and never sees the password.
/// </summary>
public static class LinuxElevation
{
    public const string PkexecPath = "/usr/bin/pkexec";

    public const string PolicyActionId = "com.axiom.firewall.install";

    public const string PolicyFilePath = "/usr/share/polkit-1/actions/com.axiom.firewall.policy";

    /// <summary>The argv pkexec receives: the executable followed by its arguments, no shell in between.</summary>
    public static IReadOnlyList<string> BuildArguments(string executable, params string[] arguments)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executable);
        ArgumentNullException.ThrowIfNull(arguments);
        return [executable, .. arguments];
    }

    public static async Task<LinuxElevationResult> RunAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Count == 0)
        {
            throw new ArgumentException("pkexec needs a program to run.", nameof(arguments));
        }

        var startInfo = new ProcessStartInfo(PkexecPath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        process.Start();
        var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var error = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        return new LinuxElevationResult(process.ExitCode, await output.ConfigureAwait(false), await error.ConfigureAwait(false));
    }
}

/// <summary>
/// Where the Linux desktop finds the daemon image: <c>&lt;app&gt;/axiomd/axiomd</c> inside the
/// published tree (the whole <c>axiomd/</c> directory is what <c>--install-service</c> copies to
/// <c>/usr/libexec/axiom</c>), or the already installed <c>/usr/libexec/axiom/axiomd</c>.
/// </summary>
public sealed class LinuxDaemonLayout
{
    public const string ImageDirectory = "/usr/libexec/axiom";

    public const string InstalledDaemonPath = ImageDirectory + "/axiomd";

    public const string UnitFilePath = "/etc/systemd/system/axiomd.service";

    public const string UnitName = "axiomd";

    public const string DaemonSubdirectory = "axiomd";

    /// <summary>Where the .deb/.rpm installs the desktop bundle (docs/LINUX_PACKAGING.md §3).</summary>
    public const string PackagePrefix = "/opt/axiom";

    public LinuxDaemonLayout(string executableDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executableDirectory);
        ExecutableDirectory = executableDirectory;
        BundledDaemonPath = Path.Combine(executableDirectory, DaemonSubdirectory, "axiomd");
        IsPackageManaged = IsUnderPackagePrefix(executableDirectory);
    }

    /// <summary>
    /// True when the desktop runs from the package prefix: the package's postinst installed the
    /// daemon (and its prerm removes it), so the desktop must not offer the pkexec install on its
    /// own at startup; a missing unit then means the package is damaged or being removed.
    /// </summary>
    public bool IsPackageManaged { get; }

    public static bool IsUnderPackagePrefix(string executableDirectory)
    {
        var directory = executableDirectory.TrimEnd('/');
        return string.Equals(directory, PackagePrefix, StringComparison.Ordinal)
            || directory.StartsWith(PackagePrefix + "/", StringComparison.Ordinal);
    }

    public static LinuxDaemonLayout Current { get; } = new(AppContext.BaseDirectory);

    public string ExecutableDirectory { get; }

    /// <summary>The daemon shipped next to the desktop; used for install and upgrade.</summary>
    public string BundledDaemonPath { get; }

    /// <summary>Install source: the bundled copy when present, else the installed image (re-run is an upgrade no-op).</summary>
    public string DaemonPath => File.Exists(BundledDaemonPath) ? BundledDaemonPath : InstalledDaemonPath;
}
