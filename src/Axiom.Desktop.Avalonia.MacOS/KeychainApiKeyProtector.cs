// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.MacOS;

/// <summary>Stores the 256-bit key that protects Axiom's local secrets.</summary>
public interface ISecretKeyStore
{
    /// <summary>Returns the stored key, or null when none exists yet.</summary>
    byte[]? Load();

    /// <summary>Stores a new key. Returns false when the store refused it.</summary>
    bool Save(byte[] key);
}

/// <summary>
/// macOS replacement for DPAPI. A random 256-bit key lives in the user's login Keychain (generic
/// password, service <c>com.axiom.firewall</c>, account <c>secret-protection-key</c>); each secret
/// (AI analyst key, reputation key, community token) is sealed with AES-256-GCM under that key and
/// only the sealed text is written to the settings files. Like DPAPI the result is bound to this
/// user, and no secret ever appears on a command line or in a log. When the Keychain refuses the
/// key, <see cref="Protect"/> throws instead of falling back to plaintext.
/// </summary>
public sealed class KeychainApiKeyProtector(ISecretKeyStore keyStore) : IApiKeyProtector
{
    public const string Prefix = "kc1:";

    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;

    private readonly object _gate = new();
    private byte[]? _key;

    public KeychainApiKeyProtector()
        : this(OperatingSystem.IsMacOS() ? new KeychainSecretKeyStore() : new UnavailableSecretKeyStore())
    {
    }

    public string Protect(string plainText)
    {
        ArgumentNullException.ThrowIfNull(plainText);
        var key = GetKey(create: true)
            ?? throw new CryptographicException("The macOS Keychain did not store Axiom's protection key.");

        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var plain = Encoding.UTF8.GetBytes(plainText);
        var cipher = new byte[plain.Length];
        var tag = new byte[TagSize];
        using (var aes = new AesGcm(key, TagSize))
        {
            aes.Encrypt(nonce, plain, cipher, tag);
        }

        CryptographicOperations.ZeroMemory(plain);
        var envelope = new byte[NonceSize + TagSize + cipher.Length];
        nonce.CopyTo(envelope, 0);
        tag.CopyTo(envelope, NonceSize);
        cipher.CopyTo(envelope, NonceSize + TagSize);
        return Prefix + Convert.ToBase64String(envelope);
    }

    public string? Unprotect(string protectedBase64)
    {
        if (string.IsNullOrWhiteSpace(protectedBase64) ||
            !protectedBase64.StartsWith(Prefix, StringComparison.Ordinal))
        {
            // A DPAPI blob copied from Windows or a damaged value cannot be opened here.
            return null;
        }

        byte[] envelope;
        try
        {
            envelope = Convert.FromBase64String(protectedBase64[Prefix.Length..]);
        }
        catch (FormatException)
        {
            return null;
        }

        if (envelope.Length < NonceSize + TagSize)
        {
            return null;
        }

        var key = GetKey(create: false);
        if (key is null)
        {
            return null;
        }

        var cipher = envelope.AsSpan(NonceSize + TagSize);
        var plain = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(
                envelope.AsSpan(0, NonceSize),
                cipher,
                envelope.AsSpan(NonceSize, TagSize),
                plain);
            return Encoding.UTF8.GetString(plain);
        }
        catch (AuthenticationTagMismatchException)
        {
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    private byte[]? GetKey(bool create)
    {
        lock (_gate)
        {
            if (_key is not null)
            {
                return _key;
            }

            var stored = keyStore.Load();
            if (stored is { Length: KeySize })
            {
                _key = stored;
                return _key;
            }

            if (!create)
            {
                return null;
            }

            var fresh = RandomNumberGenerator.GetBytes(KeySize);
            if (!keyStore.Save(fresh))
            {
                // A concurrent instance may have stored its key first: use that one.
                var raced = keyStore.Load();
                _key = raced is { Length: KeySize } ? raced : null;
                return _key;
            }

            _key = fresh;
            return _key;
        }
    }

    private sealed class UnavailableSecretKeyStore : ISecretKeyStore
    {
        public byte[]? Load() => null;

        public bool Save(byte[] key) => false;
    }
}

/// <summary>Generic-password item in the user's default (login) Keychain via Security.framework.</summary>
[SupportedOSPlatform("macos")]
public sealed class KeychainSecretKeyStore : ISecretKeyStore
{
    public const string Service = "com.axiom.firewall";
    public const string Account = "secret-protection-key";

    private const int ErrSecSuccess = 0;
    private const int ErrSecItemNotFound = -25300;
    private const int ErrSecDuplicateItem = -25299;

    public byte[]? Load()
    {
        var service = Encoding.UTF8.GetBytes(Service);
        var account = Encoding.UTF8.GetBytes(Account);
        var status = NativeMethods.SecKeychainFindGenericPassword(
            IntPtr.Zero,
            (uint)service.Length,
            service,
            (uint)account.Length,
            account,
            out var length,
            out var data,
            IntPtr.Zero);
        if (status != ErrSecSuccess || data == IntPtr.Zero)
        {
            if (status != ErrSecItemNotFound)
            {
                StartupLog.Write("keychain", $"SecKeychainFindGenericPassword failed: OSStatus {status}");
            }

            return null;
        }

        try
        {
            var encoded = new byte[length];
            Marshal.Copy(data, encoded, 0, (int)length);
            try
            {
                return Convert.FromBase64String(Encoding.ASCII.GetString(encoded));
            }
            catch (FormatException)
            {
                return null;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encoded);
            }
        }
        finally
        {
            _ = NativeMethods.SecKeychainItemFreeContent(IntPtr.Zero, data);
        }
    }

    public bool Save(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var service = Encoding.UTF8.GetBytes(Service);
        var account = Encoding.UTF8.GetBytes(Account);
        var secret = Encoding.ASCII.GetBytes(Convert.ToBase64String(key));
        try
        {
            var status = NativeMethods.SecKeychainAddGenericPassword(
                IntPtr.Zero,
                (uint)service.Length,
                service,
                (uint)account.Length,
                account,
                (uint)secret.Length,
                secret,
                IntPtr.Zero);
            if (status == ErrSecDuplicateItem)
            {
                // Another Axiom process created the key first; never overwrite it.
                return false;
            }

            if (status != ErrSecSuccess)
            {
                StartupLog.Write("keychain", $"SecKeychainAddGenericPassword failed: OSStatus {status}");
            }

            return status == ErrSecSuccess;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static class NativeMethods
    {
        private const string Security = "/System/Library/Frameworks/Security.framework/Security";

        [DllImport(Security)]
        internal static extern int SecKeychainFindGenericPassword(
            IntPtr keychainOrArray,
            uint serviceNameLength,
            byte[] serviceName,
            uint accountNameLength,
            byte[] accountName,
            out uint passwordLength,
            out IntPtr passwordData,
            IntPtr itemRef);

        [DllImport(Security)]
        internal static extern int SecKeychainAddGenericPassword(
            IntPtr keychain,
            uint serviceNameLength,
            byte[] serviceName,
            uint accountNameLength,
            byte[] accountName,
            uint passwordLength,
            byte[] passwordData,
            IntPtr itemRef);

        [DllImport(Security)]
        internal static extern int SecKeychainItemFreeContent(IntPtr attrList, IntPtr data);
    }
}
