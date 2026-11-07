// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Cryptography;
using System.Text;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.Windows;

/// <summary>Protects the optional AI API key with Windows DPAPI for the current user.</summary>
public sealed class DpapiApiKeyProtector : IApiKeyProtector
{
    public string Protect(string plainText)
    {
        ArgumentNullException.ThrowIfNull(plainText);

        var bytes = ProtectedData.Protect(
            Encoding.UTF8.GetBytes(plainText),
            optionalEntropy: null,
            DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(bytes);
    }

    public string? Unprotect(string protectedBase64)
    {
        if (string.IsNullOrWhiteSpace(protectedBase64))
        {
            return null;
        }

        var bytes = ProtectedData.Unprotect(
            Convert.FromBase64String(protectedBase64),
            optionalEntropy: null,
            DataProtectionScope.CurrentUser);
        return Encoding.UTF8.GetString(bytes);
    }
}
