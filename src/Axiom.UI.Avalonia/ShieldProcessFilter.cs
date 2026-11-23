// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Keeps Axiom Shield from asking about Windows and Microsoft-signed executables. Paths under the
/// Windows and Microsoft install roots are accepted immediately; everything else is checked for a
/// Microsoft Authenticode signer and a valid chain. Results are cached per path.
/// </summary>
internal static class ShieldProcessFilter
{
    private static readonly string WindowsRoot =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    private static readonly string ProgramFiles =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

    private static readonly string ProgramFilesX86 =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

    // CommonApplicationData is /usr/share on Unix; only the Windows ProgramData root is trusted.
    private static readonly string ProgramData = OperatingSystem.IsWindows()
        ? Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
        : string.Empty;

    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static readonly ConcurrentDictionary<string, bool> Cache =
        new(StringComparer.OrdinalIgnoreCase);

    public static bool IsIgnored(string? appPath)
    {
        if (string.IsNullOrWhiteSpace(appPath))
        {
            return false;
        }

        string path;
        try
        {
            path = Path.GetFullPath(appPath);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            return false;
        }

        if (IsUnder(path, WindowsRoot) ||
            IsUnder(path, Path.Combine(ProgramFiles, "Microsoft")) ||
            IsUnder(path, Path.Combine(ProgramFilesX86, "Microsoft")) ||
            IsUnder(path, Path.Combine(ProgramFiles, "WindowsApps")) ||
            IsUnder(path, Path.Combine(ProgramData, "Microsoft")) ||
            (OperatingSystem.IsMacOS() && (IsMacSystemPath(path) || IsMacOwnPath(path, OwnBundleRoot))))
        {
            return true;
        }

        // Axiom must never ask the user to block Axiom itself: the desktop, the service, the
        // optional modules and their runtimes live under these roots.
        if ((OperatingSystem.IsLinux() && IsLinuxOwnPath(path)) ||
            IsUnder(path, Path.Combine(LocalAppData, "Programs", "Axiom")) ||
            IsUnder(path, Path.Combine(LocalAppData, "Axiom")) ||
            IsUnder(path, Path.Combine(ProgramFiles, "Axiom")) ||
            IsUnder(path, Path.Combine(ProgramFilesX86, "Axiom")))
        {
            return true;
        }

        return Cache.GetOrAdd(path, IsMicrosoftSigned);
    }

    private static bool IsMicrosoftSigned(string path)
    {
        // Authenticode only exists on Windows; macOS signers are handled by the desktop host.
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is the API that reads Authenticode data from an executable.
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            if (!certificate.Subject.Contains("O=Microsoft Corporation", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            return chain.Build(certificate);
        }
        catch (Exception exception) when (exception is
                     CryptographicException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            // An unsigned, missing or unreadable executable is not treated as trusted.
            return false;
        }
    }

    /// <summary>
    /// macOS counterpart of the Windows directory: the sealed, SIP-protected system volume
    /// (Apple daemons and command-line tools), equivalent to ignoring C:\Windows.
    /// </summary>
    internal static bool IsMacSystemPath(string path) =>
        MacSystemRoots.Any(root => path.StartsWith(root + "/", StringComparison.Ordinal));

    /// <summary>
    /// True when <paramref name="path"/> lies inside Axiom's own .app bundle. The bundled axiomd
    /// daemon forwards Privacy Shield queries upstream itself, so prompting for it (and letting the
    /// user block it) would only break the resolver.
    /// </summary>
    internal static bool IsInOwnBundle(string path, string? bundleRoot) =>
        !string.IsNullOrEmpty(bundleRoot) &&
        path.StartsWith(bundleRoot + "/", StringComparison.Ordinal);

    /// <summary>Returns "/Applications/Axiom.app" for a base directory inside that bundle.</summary>
    internal static string? BundleRootOf(string baseDirectory)
    {
        var index = baseDirectory.IndexOf(".app/", StringComparison.Ordinal);
        return index < 0 ? null : baseDirectory[..(index + 4)];
    }

    private static readonly string? OwnBundleRoot =
        OperatingSystem.IsMacOS() ? BundleRootOf(AppContext.BaseDirectory) : null;

    /// <summary>
    /// macOS counterpart of the Program Files roots: the running bundle, the installed
    /// <c>/Applications/Axiom.app</c>, the root daemon copy launchd runs from
    /// <c>/Library/PrivilegedHelperTools/com.axiom.service</c> (PrivilegedHelperLayout.HelperDirectory
    /// in Axiom.Infrastructure.MacOS, which this assembly does not reference; the label is
    /// <see cref="Axiom.Presentation.MacBundleLayout.DaemonLabel"/>) and the activated content-filter
    /// system extension under /Library/SystemExtensions. Matched case-sensitively.
    /// </summary>
    internal static bool IsMacOwnPath(string path, string? runningBundleRoot) =>
        IsInOwnBundle(path, runningBundleRoot) ||
        MacOwnRoots.Any(root => path.StartsWith(root + "/", StringComparison.Ordinal)) ||
        IsMacFilterExtension(path);

    internal const string MacHelperDirectory =
        "/Library/PrivilegedHelperTools/" + Axiom.Presentation.MacBundleLayout.DaemonLabel;

    internal const string MacInstalledBundle = "/Applications/Axiom.app";

    /// <summary>Bundle of the AxiomFilter system extension (scripts/macos/package-app.sh EXT_ID).</summary>
    internal const string MacFilterExtensionBundle = "com.axiom.firewall.filter.systemextension";

    private static readonly string[] MacOwnRoots = [MacHelperDirectory, MacInstalledBundle];

    /// <summary>/Library/SystemExtensions/&lt;UUID&gt;/com.axiom.firewall.filter.systemextension/...</summary>
    private static bool IsMacFilterExtension(string path)
    {
        const string root = "/Library/SystemExtensions/";
        if (!path.StartsWith(root, StringComparison.Ordinal))
        {
            return false;
        }

        var parts = path[root.Length..].Split('/');
        return parts.Length > 2 && string.Equals(parts[1], MacFilterExtensionBundle, StringComparison.Ordinal);
    }

    /// <summary>
    /// Linux counterpart of the Program Files roots: the package payload (desktop and its bundled
    /// axiomd under /usr/lib/axiom-firewall, <see cref="Axiom.Presentation.LinuxDaemonLayout.PackagePrefix"/>)
    /// and the root-owned daemon image the service stages into /usr/libexec/axiom
    /// (<see cref="Axiom.Presentation.LinuxDaemonLayout.ImageDirectory"/>). Matched case-sensitively.
    /// </summary>
    internal static bool IsLinuxOwnPath(string path) =>
        LinuxOwnRoots.Any(root => path.StartsWith(root + "/", StringComparison.Ordinal));

    private static readonly string[] LinuxOwnRoots =
        [Axiom.Presentation.LinuxDaemonLayout.PackagePrefix, Axiom.Presentation.LinuxDaemonLayout.ImageDirectory];

    private static readonly string[] MacSystemRoots =
        ["/System", "/usr/libexec", "/usr/sbin", "/usr/bin", "/sbin", "/bin"];

    private static bool IsUnder(string path, string root)
    {
        if (string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        var prefix = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                     + Path.DirectorySeparatorChar;
        return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
               string.Equals(
                   path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                   root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                   StringComparison.OrdinalIgnoreCase);
    }

    private static readonly HashSet<string> CriticalSystemProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost",
        "svchost.exe",
        "system",
        "registry",
        "idle",
        "memory compression",
        "ntoskrnl",
        "ntoskrnl.exe",
        "smss",
        "smss.exe",
        "csrss",
        "csrss.exe",
        "wininit",
        "wininit.exe",
        "services",
        "services.exe",
        "lsass",
        "lsass.exe",
        "winlogon",
        "winlogon.exe",
        "spoolsv",
        "spoolsv.exe",
        "systemd-resolved",
        "systemd-networkd",
        "networkmanager",
        "dhclient",
        "mdnsresponder",
        "launchd",
        "configd",
    };

    /// <summary>
    /// True when the executable is a core OS/networking process or part of Axiom itself, where
    /// adding an outbound block rule would break DNS/DHCP/system connectivity or lock out Axiom.
    /// </summary>
    public static bool IsCriticalSystemProcess(string? appName, string? appPath)
    {
        if (!string.IsNullOrWhiteSpace(appName) && CriticalSystemProcessNames.Contains(appName.Trim()))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(appPath))
        {
            var fileName = Path.GetFileName(appPath.Trim());
            if (CriticalSystemProcessNames.Contains(fileName) || IsIgnored(appPath))
            {
                return true;
            }
        }

        return false;
    }
}
