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
            (OperatingSystem.IsMacOS() && IsMacSystemPath(path)))
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
}
