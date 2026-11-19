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

/// <summary>
/// Generic-password item in the user's login Keychain through the modern <c>SecItem*</c> API
/// (review #19). The legacy <c>SecKeychainFind/AddGenericPassword</c> bound the item's ACL to the
/// calling code's signature, so every ad hoc re-sign prompted for the Keychain password; SecItem
/// items carry <c>kSecAttrAccessible</c> instead of a per-app ACL partition and are queried by
/// attributes. Attributes: <c>kSecClass</c> = generic password, <c>kSecAttrService</c> =
/// <see cref="Service"/>, <c>kSecAttrAccount</c> = <see cref="Account"/>,
/// <c>kSecAttrAccessible</c> = after first unlock, this device only (never in iCloud Keychain or
/// backups). The secret itself is the base64 of the random key, as before, so an item written by
/// the old API stays readable (same service/account).
/// </summary>
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
        using var query = new CFDictionary();
        query.Add(SecurityConstants.kSecClass, SecurityConstants.kSecClassGenericPassword);
        query.Add(SecurityConstants.kSecAttrService, Service);
        query.Add(SecurityConstants.kSecAttrAccount, Account);
        query.Add(SecurityConstants.kSecReturnData, CoreFoundation.kCFBooleanTrue);
        query.Add(SecurityConstants.kSecMatchLimit, SecurityConstants.kSecMatchLimitOne);

        var status = NativeMethods.SecItemCopyMatching(query.Handle, out var result);
        if (status != ErrSecSuccess || result == IntPtr.Zero)
        {
            if (status != ErrSecItemNotFound)
            {
                StartupLog.Write("keychain", $"SecItemCopyMatching failed: OSStatus {status}");
            }

            return null;
        }

        try
        {
            // result is a CFData with the stored bytes.
            var length = (int)NativeMethods.CFDataGetLength(result);
            var encoded = new byte[length];
            Marshal.Copy(NativeMethods.CFDataGetBytePtr(result), encoded, 0, length);
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
            NativeMethods.CFRelease(result);
        }
    }

    public bool Save(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var secret = Encoding.ASCII.GetBytes(Convert.ToBase64String(key));
        try
        {
            using var data = CFData.FromBytes(secret);
            using var attributes = new CFDictionary();
            attributes.Add(SecurityConstants.kSecClass, SecurityConstants.kSecClassGenericPassword);
            attributes.Add(SecurityConstants.kSecAttrService, Service);
            attributes.Add(SecurityConstants.kSecAttrAccount, Account);
            attributes.Add(SecurityConstants.kSecAttrLabel, "Axiom secret protection key");
            attributes.Add(SecurityConstants.kSecAttrAccessible, SecurityConstants.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
            attributes.Add(SecurityConstants.kSecValueData, data.Handle);

            var status = NativeMethods.SecItemAdd(attributes.Handle, IntPtr.Zero);
            if (status == ErrSecDuplicateItem)
            {
                // Another Axiom process created the key first; never overwrite it.
                return false;
            }

            if (status != ErrSecSuccess)
            {
                StartupLog.Write("keychain", $"SecItemAdd failed: OSStatus {status}");
            }

            return status == ErrSecSuccess;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>
    /// Updates the stored secret in place (<c>SecItemUpdate</c>); for a future key rotation, not on the ISecretKeyStore contract.
    /// Returns false when no item exists.
    /// </summary>
    public static bool Update(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var secret = Encoding.ASCII.GetBytes(Convert.ToBase64String(key));
        try
        {
            using var query = new CFDictionary();
            query.Add(SecurityConstants.kSecClass, SecurityConstants.kSecClassGenericPassword);
            query.Add(SecurityConstants.kSecAttrService, Service);
            query.Add(SecurityConstants.kSecAttrAccount, Account);
            using var data = CFData.FromBytes(secret);
            using var changes = new CFDictionary();
            changes.Add(SecurityConstants.kSecValueData, data.Handle);
            changes.Add(SecurityConstants.kSecAttrAccessible, SecurityConstants.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);

            var status = NativeMethods.SecItemUpdate(query.Handle, changes.Handle);
            if (status != ErrSecSuccess && status != ErrSecItemNotFound)
            {
                StartupLog.Write("keychain", $"SecItemUpdate failed: OSStatus {status}");
            }

            return status == ErrSecSuccess;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>The kSec* constants are exported CFStringRef globals; read once via dlsym.</summary>
    private static class SecurityConstants
    {
        private const string Security = "/System/Library/Frameworks/Security.framework/Security";

        internal static readonly IntPtr kSecClass = CoreFoundation.Constant(Security, nameof(kSecClass));
        internal static readonly IntPtr kSecClassGenericPassword = CoreFoundation.Constant(Security, nameof(kSecClassGenericPassword));
        internal static readonly IntPtr kSecAttrService = CoreFoundation.Constant(Security, nameof(kSecAttrService));
        internal static readonly IntPtr kSecAttrAccount = CoreFoundation.Constant(Security, nameof(kSecAttrAccount));
        internal static readonly IntPtr kSecAttrLabel = CoreFoundation.Constant(Security, nameof(kSecAttrLabel));
        internal static readonly IntPtr kSecAttrAccessible = CoreFoundation.Constant(Security, nameof(kSecAttrAccessible));
        internal static readonly IntPtr kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = CoreFoundation.Constant(Security, nameof(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly));
        internal static readonly IntPtr kSecValueData = CoreFoundation.Constant(Security, nameof(kSecValueData));
        internal static readonly IntPtr kSecReturnData = CoreFoundation.Constant(Security, nameof(kSecReturnData));
        internal static readonly IntPtr kSecMatchLimit = CoreFoundation.Constant(Security, nameof(kSecMatchLimit));
        internal static readonly IntPtr kSecMatchLimitOne = CoreFoundation.Constant(Security, nameof(kSecMatchLimitOne));
    }

    private static class NativeMethods
    {
        private const string Security = "/System/Library/Frameworks/Security.framework/Security";
        private const string CF = CoreFoundation.Library;

        [DllImport(Security)]
        internal static extern int SecItemCopyMatching(IntPtr query, out IntPtr result);

        [DllImport(Security)]
        internal static extern int SecItemAdd(IntPtr attributes, IntPtr result);

        [DllImport(Security)]
        internal static extern int SecItemUpdate(IntPtr query, IntPtr attributesToUpdate);

        [DllImport(CF)]
        internal static extern nint CFDataGetLength(IntPtr data);

        [DllImport(CF)]
        internal static extern IntPtr CFDataGetBytePtr(IntPtr data);

        [DllImport(CF)]
        internal static extern void CFRelease(IntPtr handle);
    }
}

/// <summary>
/// The minimum of CoreFoundation needed for SecItem queries: a mutable dictionary whose keys are
/// the kSec* constants (not retained by us, they are process-wide globals) and whose values are
/// either constants, booleans or strings/data we create and release ourselves. Every object we
/// create follows the Create rule and is released in Dispose.
/// </summary>
[SupportedOSPlatform("macos")]
internal sealed class CFDictionary : IDisposable
{
    private readonly List<IntPtr> _owned = [];

    public CFDictionary()
    {
        Handle = CoreFoundation.CFDictionaryCreateMutable(
            IntPtr.Zero,
            0,
            CoreFoundation.Constant(CoreFoundation.Library, "kCFTypeDictionaryKeyCallBacks"),
            CoreFoundation.Constant(CoreFoundation.Library, "kCFTypeDictionaryValueCallBacks"));
        if (Handle == IntPtr.Zero)
        {
            throw new InvalidOperationException("CFDictionaryCreateMutable returned NULL.");
        }
    }

    public IntPtr Handle { get; private set; }

    /// <summary>Adds a constant or an already-owned CF object (the dictionary retains it).</summary>
    public void Add(IntPtr key, IntPtr value) => CoreFoundation.CFDictionarySetValue(Handle, key, value);

    /// <summary>Adds a managed string as a CFString (created here, released with the dictionary).</summary>
    public void Add(IntPtr key, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var text = CoreFoundation.CFStringCreateWithBytes(IntPtr.Zero, bytes, bytes.Length, CoreFoundation.UTF8Encoding, false);
        if (text == IntPtr.Zero)
        {
            throw new InvalidOperationException("CFStringCreateWithBytes returned NULL.");
        }

        _owned.Add(text);
        CoreFoundation.CFDictionarySetValue(Handle, key, text);
    }

    public void Dispose()
    {
        if (Handle != IntPtr.Zero)
        {
            CoreFoundation.CFRelease(Handle);
            Handle = IntPtr.Zero;
        }

        foreach (var handle in _owned)
        {
            CoreFoundation.CFRelease(handle);
        }

        _owned.Clear();
    }
}

/// <summary>A CFData copy of a managed buffer (the copy lives in CF memory; the caller zeroes its own).</summary>
[SupportedOSPlatform("macos")]
internal sealed class CFData : IDisposable
{
    private CFData(IntPtr handle) => Handle = handle;

    public IntPtr Handle { get; private set; }

    public static CFData FromBytes(byte[] bytes)
    {
        var handle = CoreFoundation.CFDataCreate(IntPtr.Zero, bytes, bytes.Length);
        return handle == IntPtr.Zero ? throw new InvalidOperationException("CFDataCreate returned NULL.") : new CFData(handle);
    }

    public void Dispose()
    {
        if (Handle != IntPtr.Zero)
        {
            CoreFoundation.CFRelease(Handle);
            Handle = IntPtr.Zero;
        }
    }
}

[SupportedOSPlatform("macos")]
internal static class CoreFoundation
{
    internal const string Library = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

    internal const uint UTF8Encoding = 0x08000100; // kCFStringEncodingUTF8

    internal static readonly IntPtr kCFBooleanTrue = Constant(Library, nameof(kCFBooleanTrue));

    /// <summary>
    /// Reads an exported global (a <c>CFStringRef</c> or callbacks struct) by symbol name: the
    /// symbol's address holds the pointer for CFTypeRef constants, or is the struct itself for the
    /// dictionary callbacks (which CF takes by address).
    /// </summary>
    internal static IntPtr Constant(string library, string symbol)
    {
        var handle = NativeLibrary.Load(library);
        var address = NativeLibrary.GetExport(handle, symbol);
        return symbol.EndsWith("CallBacks", StringComparison.Ordinal) ? address : Marshal.ReadIntPtr(address);
    }

    [DllImport(Library)]
    internal static extern IntPtr CFDictionaryCreateMutable(IntPtr allocator, nint capacity, IntPtr keyCallBacks, IntPtr valueCallBacks);

    [DllImport(Library)]
    internal static extern void CFDictionarySetValue(IntPtr dictionary, IntPtr key, IntPtr value);

    [DllImport(Library)]
    internal static extern IntPtr CFStringCreateWithBytes(IntPtr allocator, byte[] bytes, nint length, uint encoding, [MarshalAs(UnmanagedType.I1)] bool isExternalRepresentation);

    [DllImport(Library)]
    internal static extern IntPtr CFDataCreate(IntPtr allocator, byte[] bytes, nint length);

    [DllImport(Library)]
    internal static extern void CFRelease(IntPtr handle);
}
