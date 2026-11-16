// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Axiom.Contracts.Blackbox;
using Axiom.Presentation;

namespace Axiom.GraphSnapshotTool;

internal static class Program
{
    private const string DefaultMinClientVersion = "0.54.0";

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintUsage();
            return 0;
        }

        var command = args[0].ToLowerInvariant();
        var options = ParseOptions(args.Skip(1).ToArray());

        try
        {
            return command switch
            {
                "init-key" => RunInitKey(options),
                "build" => await RunBuildAsync(options).ConfigureAwait(false),
                "verify" => RunVerify(options),
                _ => Fail($"Unknown command '{args[0]}'."),
            };
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Error: {exception.Message}");
            return 1;
        }
    }

    private static int RunInitKey(Dictionary<string, string> options)
    {
        var keyOut = options.TryGetValue("--key-out", out var explicitOut)
            ? Path.GetFullPath(explicitOut)
            : GetDefaultKeyPath();

        if (File.Exists(keyOut) && !options.ContainsKey("--force"))
        {
            throw new InvalidOperationException(
                $"Private key already exists at '{keyOut}'. Pass --force to overwrite or use --key-out.");
        }

        var parent = Path.GetDirectoryName(keyOut);
        if (!string.IsNullOrEmpty(parent))
        {
            Directory.CreateDirectory(parent);
        }

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privatePem = key.ExportPkcs8PrivateKeyPem();
        var publicSpkiBase64 = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

        File.WriteAllText(keyOut, privatePem, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        RestrictFilePermissions(keyOut);

        Console.WriteLine($"Private key saved (keep secret, never commit): {keyOut}");
        Console.WriteLine();
        Console.WriteLine("Pinned SPKI public key (paste into VerifiedGraphPeerRelay.DefaultCuratorPublicKeyDerBase64");
        Console.WriteLine("or pass via AXIOM_GRAPH_TRUST_KEY):");
        Console.WriteLine(publicSpkiBase64);
        return 0;
    }

    private static async Task<int> RunBuildAsync(Dictionary<string, string> options)
    {
        var keyPath = options.TryGetValue("--key", out var explicitKey)
            ? Path.GetFullPath(explicitKey)
            : GetDefaultKeyPath();
        if (!File.Exists(keyPath))
        {
            throw new FileNotFoundException($"Curator private key PEM not found at '{keyPath}'. Run init-key first.");
        }

        var outPath = options.TryGetValue("--out", out var explicitOut)
            ? Path.GetFullPath(explicitOut)
            : Path.GetFullPath(Path.Combine("artifacts", "verified-graph", "verified-graph-snapshot.json"));
        var blackboxUrl = options.TryGetValue("--blackbox-url", out var urlText)
            ? new Uri(urlText)
            : new Uri("http://127.0.0.1:9700/");
        var minClientVersion = options.TryGetValue("--min-client-version", out var ver) && !string.IsNullOrWhiteSpace(ver)
            ? ver.Trim()
            : DefaultMinClientVersion;
        var limit = options.TryGetValue("--limit", out var limitRaw) &&
                    int.TryParse(limitRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedLimit)
            ? Math.Clamp(parsedLimit, 1, 500)
            : 500;

        long sequence = 0;
        if (options.TryGetValue("--sequence", out var seqRaw))
        {
            if (!long.TryParse(seqRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out sequence) || sequence < 1)
            {
                throw new InvalidOperationException("--sequence must be a positive integer.");
            }
        }
        else if (options.TryGetValue("--previous-snapshot", out var prevPath) && File.Exists(prevPath))
        {
            var prevBytes = await File.ReadAllBytesAsync(prevPath).ConfigureAwait(false);
            var prevEnvelope = VerifiedGraphPeerRelay.TryParseEnvelopeUtf8(prevBytes);
            if (prevEnvelope is not null && prevEnvelope.SequenceNumber >= 1)
            {
                sequence = prevEnvelope.SequenceNumber + 1;
            }
        }

        if (sequence < 1)
        {
            sequence = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        using var key = ECDsa.Create();
        var pem = await File.ReadAllTextAsync(keyPath).ConfigureAwait(false);
        key.ImportFromPem(pem);
        var publicKeyBase64 = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

        using var client = new BlackboxDashboardClient(baseUri: blackboxUrl);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var sync = await client.GetVerifiedSyncAsync(cts.Token).ConfigureAwait(false);
        var page = await client.GetVerifiedGraphAsync(limit, offset: 0, cts.Token).ConfigureAwait(false);

        if (sync.VerifiedRules <= 0 || page.Threats.Count == 0)
        {
            throw new InvalidOperationException(
                $"Local Blackbox does not have enough verified public graph data (verified_rules={sync.VerifiedRules}, threats={page.Threats.Count}). Sync Blackbox first.");
        }

        var now = DateTimeOffset.UtcNow;
        var envelope = VerifiedGraphPeerRelay.CreateSignedEnvelope(
            sync,
            page,
            key,
            publicKeyBase64,
            now,
            sequence,
            minClientVersion)
            ?? throw new InvalidOperationException("Failed to create signed envelope: payload failed validation.");

        var bytes = VerifiedGraphPeerRelay.WriteEnvelopeUtf8(envelope);
        var verified = VerifiedGraphPeerRelay.TryVerifyAndSanitize(
            envelope,
            now,
            publicKeyBase64,
            peerEndpoint: "self-check",
            maxAge: VerifiedGraphPeerRelay.SnapshotFreshnessWindow)
            ?? throw new InvalidOperationException("Self-verification of generated snapshot failed.");

        var outDir = Path.GetDirectoryName(outPath);
        if (!string.IsNullOrEmpty(outDir))
        {
            Directory.CreateDirectory(outDir);
        }

        await File.WriteAllBytesAsync(outPath, bytes).ConfigureAwait(false);

        var fileHash = Convert.ToHexStringLower(SHA256.HashData(bytes));
        var shaPath = outPath + ".sha256";
        var shaLine = $"{fileHash}  {Path.GetFileName(outPath)}{Environment.NewLine}";
        await File.WriteAllTextAsync(shaPath, shaLine, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)).ConfigureAwait(false);

        Console.WriteLine($"Snapshot written: {outPath}");
        Console.WriteLine($"Checksum written: {shaPath}");
        Console.WriteLine($"Sequence:         {verified.SequenceNumber}");
        Console.WriteLine($"Verified rules:   {verified.Sync.VerifiedRules}");
        Console.WriteLine($"Threats bundled:  {verified.Graph.Threats.Count}");
        Console.WriteLine($"Payload bytes:    {bytes.Length}");
        Console.WriteLine($"Merkle root:      {verified.MerkleRootHex}");
        Console.WriteLine($"Public key SPKI:  {publicKeyBase64}");
        return 0;
    }

    private static int RunVerify(Dictionary<string, string> options)
    {
        if (!options.TryGetValue("--file", out var filePath) || !File.Exists(filePath))
        {
            throw new FileNotFoundException("Pass --file <snapshot.json> pointing to an existing snapshot.");
        }

        var pubKey = options.TryGetValue("--pubkey", out var explicitPubKey)
            ? explicitPubKey
            : VerifiedGraphPeerRelay.DefaultCuratorPublicKeyDerBase64;
        if (string.IsNullOrWhiteSpace(pubKey))
        {
            throw new InvalidOperationException("Pass --pubkey <SPKI_BASE64> or set DefaultCuratorPublicKeyDerBase64.");
        }

        var bytes = File.ReadAllBytes(filePath);
        var envelope = VerifiedGraphPeerRelay.TryParseEnvelopeUtf8(bytes)
            ?? throw new InvalidOperationException("Snapshot failed strict UTF-8 JSON schema validation.");

        var verified = VerifiedGraphPeerRelay.TryVerifyAndSanitize(
            envelope,
            DateTimeOffset.UtcNow,
            pubKey,
            peerEndpoint: filePath,
            maxAge: VerifiedGraphPeerRelay.SnapshotFreshnessWindow)
            ?? throw new InvalidOperationException("Snapshot failed ECDSA signature, Merkle, SHA-256, or freshness verification.");

        Console.WriteLine(
            $"OK: seq={verified.SequenceNumber}, rules={verified.Sync.VerifiedRules}, threats={verified.Graph.Threats.Count}, merkle={verified.MerkleRootHex}");
        return 0;
    }

    private static string GetDefaultKeyPath() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".axiom",
            "verified-graph-curator.key.pem");

    private static void RestrictFilePermissions(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            var info = new FileInfo(path);
            var security = info.GetAccessControl();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var user = WindowsIdentity.GetCurrent().User;
            if (user is not null)
            {
                security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, AccessControlType.Allow));
                info.SetAccessControl(security);
            }
        }
        else if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    private static Dictionary<string, string> ParseOptions(string[] args)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Length; i++)
        {
            var token = args[i];
            if (!token.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                map[token] = args[i + 1];
                i++;
            }
            else
            {
                map[token] = "true";
            }
        }

        return map;
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        PrintUsage();
        return 1;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Axiom Verified Graph Snapshot Publisher Tool");
        Console.WriteLine("Commands:");
        Console.WriteLine("  init-key [--key-out <path>] [--force]");
        Console.WriteLine("  build    [--key <path>] [--out <path>] [--previous-snapshot <path>] [--sequence <n>] [--limit <1..500>]");
        Console.WriteLine("  verify   --file <path> [--pubkey <SPKI_BASE64>]");
    }
}
