// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// Protects the optional AI provider API key at rest. The Windows host uses DPAPI for the current
/// user; a host without a protector must refuse to store a key rather than write plaintext.
/// </summary>
public interface IApiKeyProtector
{
    string Protect(string plainText);

    string? Unprotect(string protectedBase64);
}

/// <summary>Refuses to protect a secret. It never falls back to plaintext storage.</summary>
public sealed class UnsupportedApiKeyProtector : IApiKeyProtector
{
    public string Protect(string plainText) =>
        throw new NotSupportedException("This host has no secret protector.");

    public string? Unprotect(string protectedBase64) => null;
}
