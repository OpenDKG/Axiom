// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.Linux;

/// <summary>Stores the 256-bit key that protects Axiom's local secrets.</summary>
public interface ISecretKeyStore
{
    /// <summary>Returns the stored key, or null when none exists yet.</summary>
    byte[]? Load();

    /// <summary>Stores a new key. Returns false when the store refused it.</summary>
    bool Save(byte[] key);
}

/// <summary>
/// Linux replacement for DPAPI, same envelope as the macOS Keychain protector. A random 256-bit key
/// is kept in the user's Secret Service keyring (<c>org.freedesktop.secrets</c>, item attributes
/// service=<c>com.axiom.firewall</c> account=<c>secret-protection-key</c>) through <c>secret-tool</c>
/// when libsecret's CLI is installed, otherwise in a 0600 file under <c>$XDG_STATE_HOME/axiom</c>
/// (0700 directory). Each secret (AI analyst key, reputation key, community token) is sealed with
/// AES-256-GCM under that key and only the sealed text is written to the settings files. No secret
/// ever appears on a command line or in a log (secret-tool reads the key from stdin). When neither
/// store accepts the key, <see cref="Protect"/> throws instead of falling back to plaintext.
/// </summary>
public sealed class SecretServiceApiKeyProtector(ISecretKeyStore keyStore) : IApiKeyProtector
{
    public const string Prefix = "ss1:";

    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;

    private readonly object _gate = new();
    private byte[]? _key;

    public SecretServiceApiKeyProtector()
        : this(SecretKeyStores.Default())
    {
    }

    public string Protect(string plainText)
    {
        ArgumentNullException.ThrowIfNull(plainText);
        var key = GetKey(create: true)
            ?? throw new CryptographicException("Neither the Secret Service keyring nor the state directory stored Axiom's protection key.");

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

/// <summary>Chooses the key store for this host. Pure selection, unit-tested.</summary>
public static class SecretKeyStores
{
    public const string SecretToolName = "secret-tool";

    public static ISecretKeyStore Default() =>
        Choose(FindOnPath(SecretToolName), new FileSecretKeyStore());

    /// <summary>secret-tool when present (keyring first, file as fallback), else the file alone.</summary>
    internal static ISecretKeyStore Choose(string? secretToolPath, ISecretKeyStore fileStore) =>
        secretToolPath is null ? fileStore : new ChainedSecretKeyStore(new SecretToolKeyStore(secretToolPath), fileStore);

    internal static string? FindOnPath(string name)
    {
        var path = Environment.GetEnvironmentVariable("PATH") ?? "/usr/bin:/bin";
        foreach (var directory in path.Split(':', StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(directory, name);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }
}

/// <summary>Reads from the first store that has a key; saves to the first that accepts it.</summary>
public sealed class ChainedSecretKeyStore(params ISecretKeyStore[] stores) : ISecretKeyStore
{
    public byte[]? Load()
    {
        foreach (var store in stores)
        {
            if (store.Load() is { } key)
            {
                return key;
            }
        }

        return null;
    }

    public bool Save(byte[] key)
    {
        foreach (var store in stores)
        {
            if (store.Save(key))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>
/// 0600 file <c>$XDG_STATE_HOME/axiom/secret-protection-key</c> (base64) in a 0700 directory. Same
/// trust level as the settings files it protects: another process of this user can read it, which
/// is the DPAPI/Keychain-without-prompt model too; other users and the daemon cannot.
/// </summary>
public sealed class FileSecretKeyStore(string? path = null) : ISecretKeyStore
{
    public const string FileName = "secret-protection-key";

    private readonly string _path = path ?? Path.Combine(LinuxPaths.StateDirectory, FileName);

    public string KeyPath => _path;

    public byte[]? Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return null;
            }

            return Convert.FromBase64String(File.ReadAllText(_path).Trim());
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or FormatException)
        {
            return null;
        }
    }

    public bool Save(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        try
        {
            var directory = Path.GetDirectoryName(_path)!;
            Directory.CreateDirectory(directory);
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            if (File.Exists(_path))
            {
                // Another Axiom process created the key first; never overwrite it.
                return false;
            }

            var temporary = _path + ".tmp";
            using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                var text = Encoding.ASCII.GetBytes(Convert.ToBase64String(key) + "\n");
                stream.Write(text);
            }

            File.Move(temporary, _path, overwrite: false);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            StartupLog.Write("secrets", "file key store failed: " + exception.Message);
            return false;
        }
    }
}

/// <summary>
/// libsecret's <c>secret-tool</c>: <c>lookup</c> prints the secret to stdout, <c>store</c> reads it
/// from stdin; the attributes identify the item and nothing secret is on the command line.
/// </summary>
public sealed class SecretToolKeyStore(string secretToolPath) : ISecretKeyStore
{
    public const string Service = "com.axiom.firewall";
    public const string Account = "secret-protection-key";

    public static IReadOnlyList<string> LookupArguments => ["lookup", "service", Service, "account", Account];

    public static IReadOnlyList<string> StoreArguments =>
        ["store", "--label=Axiom secret protection key", "service", Service, "account", Account];

    public byte[]? Load()
    {
        try
        {
            using var process = Process.Start(StartInfo(LookupArguments, redirectInput: false));
            if (process is null)
            {
                return null;
            }

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(10_000);
            if (!process.HasExited || process.ExitCode != 0)
            {
                return null;
            }

            try
            {
                return Convert.FromBase64String(output.Trim());
            }
            catch (FormatException)
            {
                return null;
            }
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return null;
        }
    }

    public bool Save(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (Load() is not null)
        {
            return false;
        }

        try
        {
            using var process = Process.Start(StartInfo(StoreArguments, redirectInput: true));
            if (process is null)
            {
                return false;
            }

            process.StandardInput.Write(Convert.ToBase64String(key));
            process.StandardInput.Close();
            process.WaitForExit(30_000);
            if (!process.HasExited)
            {
                process.Kill();
                return false;
            }

            if (process.ExitCode != 0)
            {
                StartupLog.Write("secrets", $"secret-tool store exited with {process.ExitCode}");
            }

            return process.ExitCode == 0;
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return false;
        }
    }

    private ProcessStartInfo StartInfo(IReadOnlyList<string> arguments, bool redirectInput)
    {
        var startInfo = new ProcessStartInfo(secretToolPath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = redirectInput,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return startInfo;
    }
}
