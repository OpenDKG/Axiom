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

    private static readonly string ProgramData =
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private const int SignatureCacheLimit = 512;
    private static readonly TimeSpan SignatureCacheLifetime = TimeSpan.FromMinutes(5);
    private static readonly object SignatureCacheWriteGate = new();
    private static readonly ConcurrentDictionary<string, (bool Trusted, DateTimeOffset Expires)> Cache =
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
            IsUnder(path, Path.Combine(ProgramData, "Microsoft")))
        {
            return true;
        }

        // Axiom must never ask the user to block Axiom itself: the desktop, the service, the
        // optional modules and their runtimes live under these roots.
        if (IsUnder(path, Path.Combine(LocalAppData, "Programs", "Axiom")) ||
            IsUnder(path, Path.Combine(LocalAppData, "Axiom")) ||
            IsUnder(path, Path.Combine(ProgramFiles, "Axiom")) ||
            IsUnder(path, Path.Combine(ProgramFilesX86, "Axiom")))
        {
            return true;
        }

        var now = DateTimeOffset.UtcNow;
        if (Cache.TryGetValue(path, out var cached) && cached.Expires > now)
        {
            return cached.Trusted;
        }

        var trusted = IsMicrosoftSigned(path);
        lock (SignatureCacheWriteGate)
        {
            if (Cache.Count >= SignatureCacheLimit && !Cache.ContainsKey(path))
            {
                foreach (var oldest in Cache.OrderBy(pair => pair.Value.Expires).Take(128))
                {
                    Cache.TryRemove(oldest.Key, out _);
                }
            }

            Cache[path] = (trusted, now + SignatureCacheLifetime);
        }

        return trusted;
    }

    private static bool IsMicrosoftSigned(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is the API that reads Authenticode data from an executable.
            using var signer = X509Certificate.CreateFromSignedFile(path);
            using var certificate = new X509Certificate2(signer);
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
