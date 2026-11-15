// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security.Cryptography;

namespace Axiom.Presentation;

/// <summary>
/// Normalizes Windows CRLF endings in Blackbox's shipped BIP-39 wordlist back to LF so its bytes
/// match the upstream pinned SHA-256 and seed-phrase detection stays active.
/// </summary>
public static class BlackboxWordlistNormalizer
{
    public const string PinnedBip39Sha256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

    private static readonly string[] RelativeWordlistPath =
    [
        "plugins",
        "blackbox",
        "kernel",
        "crypto_secrets",
        "bip39_english.txt",
    ];

    /// <summary>All locations where the vendor installer or plugin sync may place bip39_english.txt.</summary>
    public static IReadOnlyList<string> CandidatePaths(string localAppData, string userProfile) =>
    [
        Path.Combine([localAppData, "Axiom", "modules", "blackbox", "agent-blackbox", .. RelativeWordlistPath]),
        Path.Combine([localAppData, "hermes", .. RelativeWordlistPath]),
        Path.Combine([userProfile, ".hermes", .. RelativeWordlistPath]),
    ];

    /// <summary>
    /// Repairs CRLF line endings in every existing wordlist copy whose LF content matches
    /// <see cref="PinnedBip39Sha256"/>. Returns how many valid LF copies exist afterward.
    /// </summary>
    public static int NormalizeAll(string? localAppData = null, string? userProfile = null)
    {
        var local = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var profile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var validCount = 0;

        foreach (var path in CandidatePaths(local, profile))
        {
            if (NormalizeFile(path))
            {
                validCount++;
            }
        }

        return validCount;
    }

    /// <summary>Normalizes a single file in place when removing CR produces <paramref name="expectedSha256"/>.</summary>
    public static bool NormalizeFile(string path, string expectedSha256 = PinnedBip39Sha256)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            !File.Exists(path) ||
            StorageSafety.IsReparsePointInPath(path))
        {
            return false;
        }

        try
        {
            var raw = File.ReadAllBytes(path);
            var stripped = StripCarriageReturns(raw);
            var digest = Convert.ToHexStringLower(SHA256.HashData(stripped));
            if (!string.Equals(digest, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (stripped.Length != raw.Length)
            {
                File.WriteAllBytes(path, stripped);
            }

            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static byte[] StripCarriageReturns(byte[] bytes)
    {
        var buffer = new byte[bytes.Length];
        var count = 0;
        for (var i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] == (byte)'\r' && i + 1 < bytes.Length && bytes[i + 1] == (byte)'\n')
            {
                continue;
            }

            buffer[count++] = bytes[i];
        }

        if (count == bytes.Length)
        {
            return bytes;
        }

        var trimmed = new byte[count];
        Array.Copy(buffer, trimmed, count);
        return trimmed;
    }
}
