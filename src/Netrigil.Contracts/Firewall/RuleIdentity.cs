// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Cryptography;
using System.Text;
namespace Netrigil.Contracts.Firewall;

/// <summary>
/// Deterministic identity for an app-scoped rule. The same executable path and direction always
/// produce the same managed rule id, so block, re-block and unblock address the same OS rule.
/// </summary>
public static class RuleIdentity
{
    public static Guid ForApp(string executablePath, FirewallDirection direction)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);

        var normalized = NormalizePath(executablePath);
        var input = string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{normalized}|{(int)direction}");
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));

        Span<byte> bytes = stackalloc byte[16];
        hash.AsSpan(0, 16).CopyTo(bytes);

        // RFC 4122 version 5 (name-based, SHA-256 variant) bits, so the id is a valid UUID.
        bytes[7] = (byte)((bytes[7] & 0x0F) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);

        return new Guid(bytes);
    }

    public static string NormalizePath(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);

        return executablePath.Trim().Replace('/', '\\').ToLowerInvariant();
    }
}
