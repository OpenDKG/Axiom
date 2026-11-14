// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Axiom.Contracts.Blackbox;

namespace Axiom.Presentation;

/// <summary>
/// Cryptographically signed, RAM-only manifest and snapshot envelope exchanged between active
/// Axiom instances on a LAN or Host/VM bridge. Contains passive threat metadata only and is
/// never written to disk.
/// </summary>
public sealed record VerifiedGraphPeerEnvelope(
    int Version,
    long SequenceNumber,
    long CreatedUtcTicks,
    string MinClientVersion,
    int VerifiedRulesCount,
    int TotalThreats,
    string PayloadSha256Hex,
    string MerkleRootHex,
    string PublicKeyDerBase64,
    string SignatureBase64,
    IReadOnlyList<BlackboxGraphThreat> Threats,
    IReadOnlyDictionary<string, int> CategoryTotals);

/// <summary>Result of validating and loading a peer-verified graph snapshot into RAM.</summary>
public sealed record VerifiedGraphPeerSnapshot(
    BlackboxVerifiedSync Sync,
    BlackboxGraphPage Graph,
    long SequenceNumber,
    string MerkleRootHex,
    string PeerEndpoint);

/// <summary>
/// Shares an already-synced public Verified Graph directly from RAM between explicitly trusted
/// Axiom peers (opt-in LAN / Host-VM cache or signed snapshot endpoint) so another instance does not
/// need to wait for slow per-asset DKG downloads.
///
/// Security invariants:
/// 1. Fail-closed trust model: a pinned curator/cluster SPKI public key (<c>AXIOM_GRAPH_TRUST_KEY</c>
///    or constructor argument) is mandatory; self-signed or unpinned peer payloads are always rejected
///    and Axiom falls back cleanly to the local Blackbox/DKG node.
/// 2. RAM-only &amp; zero-reflection: both serialization (<see cref="Utf8JsonWriter"/>) and parsing
///    (<see cref="Utf8JsonReader"/>) run strictly in memory over bounded buffers (4 MiB max, 2 s I/O
///    timeout) without reflection, temporary files, or unknown-field tolerance.
/// 3. Anti-rollback &amp; integrity: enforces monotonic <see cref="VerifiedGraphPeerEnvelope.SequenceNumber"/>,
///    monotonic freshness timestamps (±15 minutes), <see cref="VerifiedGraphPeerEnvelope.MinClientVersion"/>,
///    canonical payload SHA-256, binary SHA-256 Merkle root, and ECDSA P-256 signature verification.
/// 4. Strict passive-data whitelist: every field is validated against strict domain/IP/hash/safe-token
///    formats; path traversal, control characters, shell metacharacters, unknown JSON fields, or
///    disallowed categories reject the entire envelope.
/// </summary>
public sealed partial class VerifiedGraphPeerRelay : IDisposable
{
    public const int DefaultPort = 19701;

    private const int EnvelopeVersion = 1;

    private const int MaxEnvelopeBytes = 4 * 1024 * 1024;

    private const int MaxThreats = 500;

    private const int MaxTextLength = 160;

    private const string DiscoveryRequest = "AXIOM_GRAPH_DISCOVER_V1";

    private const string DiscoveryResponsePrefix = "AXIOM_GRAPH_OFFER_V1:";

    private static readonly TimeSpan FreshnessWindow = TimeSpan.FromMinutes(15);

    private static readonly TimeSpan ReSignInterval = TimeSpan.FromMinutes(5);

    private static readonly TimeSpan NetworkTimeout = TimeSpan.FromSeconds(2);

    private static readonly HttpClient SharedSnapshotHttpClient = new(
        new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = NetworkTimeout,
            MaxResponseHeadersLength = 16,
        },
        disposeHandler: true)
    {
        Timeout = NetworkTimeout,
    };

    private static readonly HashSet<string> AllowedCategories = new(StringComparer.Ordinal)
    {
        "dependency",
        "injection",
        "escalation",
        "fileaccess",
        "skill",
        "secret",
        "ioc",
        "other",
    };

    private static readonly HashSet<string> AllowedSeverities = new(StringComparer.Ordinal)
    {
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "unknown",
    };

    private static readonly HashSet<string> AllowedSources = new(StringComparer.Ordinal)
    {
        "public",
        "verified",
    };

    [GeneratedRegex(
        @"^(?=.{1,160}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$",
        RegexOptions.CultureInvariant)]
    private static partial Regex DomainRegex();

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._:@/+=-]{0,159}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeTokenRegex();

    private readonly object _gate = new();
    private readonly ECDsa? _signingKey;
    private readonly bool _ownsSigningKey;
    private readonly string _signingPublicKeyDerBase64;
    private readonly int _listenPort;
    private readonly IPAddress _listenAddress;
    private readonly string? _pinnedPublicKeyDerBase64;
    private readonly IReadOnlyList<string>? _explicitPeersOverride;
    private readonly Uri? _snapshotEndpointUri;
    private readonly bool _enableLanBroadcast;
    private readonly bool _optInEnabled;
    private readonly Version _clientVersion;
    private readonly string _minClientVersion;

    private byte[]? _currentEnvelopeBytes;
    private int _currentRulesCount;
    private long _publishSequence;
    private BlackboxVerifiedSync? _lastSync;
    private BlackboxGraphPage? _lastPage;
    private DateTimeOffset _lastSignedUtc = DateTimeOffset.MinValue;

    private long _highestAcceptedSequence;
    private long _highestAcceptedTicks;
    private string _highestAcceptedMerkle = string.Empty;

    private TcpListener? _tcpListener;
    private UdpClient? _udpResponder;
    private CancellationTokenSource? _listenerCts;
    private int _activeListenPort;
    private bool _disposed;

    /// <summary>
    /// Creates a peer relay / signed-snapshot verifier. By default (with no arguments), networking
    /// is disabled unless both a pinned trust key (<c>AXIOM_GRAPH_TRUST_KEY</c> or
    /// <c>AXIOM_GRAPH_CURATOR_PUBKEY</c>) and an opt-in source (<c>AXIOM_GRAPH_SNAPSHOT_URL</c>,
    /// <c>AXIOM_GRAPH_PEERS</c>, <c>AXIOM_GRAPH_LAN=1</c>, or <c>AXIOM_GRAPH_LAN_CACHE=1</c>) are
    /// explicitly configured.
    /// </summary>
    public VerifiedGraphPeerRelay(
        int listenPort = DefaultPort,
        IPAddress? listenAddress = null,
        string? pinnedPublicKeyDerBase64 = null,
        ECDsa? curatorSigningKey = null,
        IReadOnlyList<string>? explicitPeersOverride = null,
        bool enableLanBroadcast = false,
        bool? optInOverride = null,
        Version? clientVersion = null,
        string minClientVersion = "0.17.0",
        Uri? snapshotEndpointOverride = null)
    {
        _listenPort = listenPort;
        _listenAddress = listenAddress ?? IPAddress.Loopback;
        _pinnedPublicKeyDerBase64 = string.IsNullOrWhiteSpace(pinnedPublicKeyDerBase64)
            ? (ReadEnv("AXIOM_GRAPH_TRUST_KEY") ?? ReadEnv("AXIOM_GRAPH_CURATOR_PUBKEY"))
            : pinnedPublicKeyDerBase64.Trim();
        _explicitPeersOverride = explicitPeersOverride;
        _clientVersion = NormalizeVersion(
            clientVersion ?? typeof(VerifiedGraphPeerRelay).Assembly.GetName().Version ?? new Version(0, 17, 0));
        _minClientVersion = string.IsNullOrWhiteSpace(minClientVersion) ? "0.17.0" : minClientVersion.Trim();

        var envPeers = ReadEnv("AXIOM_GRAPH_PEERS");
        var envLan = string.Equals(ReadEnv("AXIOM_GRAPH_LAN"), "1", StringComparison.Ordinal) ||
                     string.Equals(ReadEnv("AXIOM_GRAPH_LAN_CACHE"), "1", StringComparison.Ordinal);
        _enableLanBroadcast = enableLanBroadcast || envLan;
        _snapshotEndpointUri = snapshotEndpointOverride is not null
            ? (IsAllowedSnapshotUri(snapshotEndpointOverride) ? snapshotEndpointOverride : null)
            : TryParseAllowedSnapshotUri(ReadEnv("AXIOM_GRAPH_SNAPSHOT_URL"));

        // Fail closed: without an explicit opt-in or pinned trust key, never open sockets or
        // accept peer payloads (always fall back directly to local Blackbox/DKG).
        _optInEnabled = optInOverride ??
                        (!string.IsNullOrWhiteSpace(_pinnedPublicKeyDerBase64) &&
                         (_snapshotEndpointUri is not null ||
                          !string.IsNullOrWhiteSpace(envPeers) ||
                          _enableLanBroadcast ||
                          _explicitPeersOverride is { Count: > 0 }));

        if (curatorSigningKey is not null)
        {
            _signingKey = curatorSigningKey;
            _ownsSigningKey = false;
            _signingPublicKeyDerBase64 = Convert.ToBase64String(curatorSigningKey.ExportSubjectPublicKeyInfo());
        }
        else if (_optInEnabled)
        {
            _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            _ownsSigningKey = true;
            _signingPublicKeyDerBase64 = Convert.ToBase64String(_signingKey.ExportSubjectPublicKeyInfo());
        }
        else
        {
            _signingPublicKeyDerBase64 = string.Empty;
        }
    }

    public int ListeningPort => Volatile.Read(ref _activeListenPort);

    public string PublicKeyDerBase64 => _signingPublicKeyDerBase64;

    public bool IsEnabled => _optInEnabled;

    /// <summary>
    /// Stores the verified graph snapshot exclusively in RAM, signs it with the configured key,
    /// and ensures the in-memory TCP/UDP relay listeners are active. Returns true only when opt-in
    /// is enabled and serialization succeeds within bounds.
    /// </summary>
    public bool PublishInMemory(BlackboxVerifiedSync sync, BlackboxGraphPage page)
    {
        ArgumentNullException.ThrowIfNull(sync);
        ArgumentNullException.ThrowIfNull(page);

        if (_disposed || !_optInEnabled || _signingKey is null || sync.VerifiedRules <= 0 || page.Threats.Count == 0)
        {
            return false;
        }

        var now = DateTimeOffset.UtcNow;
        byte[] bytes;
        lock (_gate)
        {
            if (_disposed || _signingKey is null)
            {
                return false;
            }

            var nextSequence = _publishSequence + 1;
            var envelope = CreateSignedEnvelope(
                sync,
                page,
                _signingKey,
                _signingPublicKeyDerBase64,
                now,
                nextSequence,
                _minClientVersion);
            if (envelope is null)
            {
                return false;
            }

            bytes = WriteEnvelopeUtf8(envelope);
            if (bytes.Length > MaxEnvelopeBytes)
            {
                return false;
            }

            _publishSequence = nextSequence;
            _lastSync = sync;
            _lastPage = page;
            _lastSignedUtc = now;
            _currentRulesCount = sync.VerifiedRules;
            _currentEnvelopeBytes = bytes;
            EnsureListenersStartedLocked();
        }

        return true;
    }

    /// <summary>
    /// Validates and parses an optional Tier (a) curator-signed snapshot URI.
    /// Accepts <c>https://</c> endpoints without userinfo or loopback <c>http://</c> gateways
    /// (<c>127.0.0.1</c>, <c>::1</c>, <c>localhost</c>); rejects non-loopback plain <c>http://</c>
    /// and all other schemes.
    /// </summary>
    public static Uri? TryParseAllowedSnapshotUri(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw) ||
            !Uri.TryCreate(raw.Trim(), UriKind.Absolute, out var uri))
        {
            return null;
        }

        return IsAllowedSnapshotUri(uri) ? uri : null;
    }

    private static bool IsAllowedSnapshotUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            string.IsNullOrWhiteSpace(uri.Host))
        {
            return false;
        }

        if (uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return string.Equals(uri.DnsSafeHost, "localhost", StringComparison.OrdinalIgnoreCase) ||
               (IPAddress.TryParse(uri.DnsSafeHost, out var ip) && IPAddress.IsLoopback(ip));
    }

    /// <summary>
    /// Fetches a curator-signed manifest snapshot from Tier (a) (<c>AXIOM_GRAPH_SNAPSHOT_URL</c>)
    /// or Tier (b) opt-in LAN / Host-VM cache peers strictly in RAM using zero-reflection
    /// <see cref="Utf8JsonReader"/> parsing, rejecting unknown fields, enforcing the mandatory
    /// pinned trust key, verifying payload SHA-256 + Merkle root + timestamp + monotonic sequence,
    /// and returning null on any failure so Axiom cleanly falls back to the local DKG node.
    /// </summary>
    public async Task<VerifiedGraphPeerSnapshot?> TryFetchFromPeersAsync(
        int currentLocalRules,
        CancellationToken cancellationToken)
    {
        if (_disposed || !_optInEnabled || string.IsNullOrWhiteSpace(_pinnedPublicKeyDerBase64))
        {
            return null;
        }

        // Tier (a): curator-signed snapshot endpoint (HTTPS CDN or loopback DKG gateway).
        if (_snapshotEndpointUri is not null)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var endpointBytes = await TryFetchRawSnapshotFromUriAsync(_snapshotEndpointUri, cancellationToken)
                .ConfigureAwait(false);
            if (endpointBytes is { Length: > 0 and <= MaxEnvelopeBytes })
            {
                var snapshot = VerifyIncomingEnvelopeBytes(
                    endpointBytes,
                    DateTimeOffset.UtcNow,
                    _snapshotEndpointUri.GetLeftPart(UriPartial.Authority));
                if (snapshot is not null && snapshot.Sync.VerifiedRules > currentLocalRules)
                {
                    if (_enableLanBroadcast)
                    {
                        CacheCuratorSignedEnvelopeInMemory(endpointBytes, snapshot.Sync.VerifiedRules);
                    }

                    return snapshot;
                }
            }
        }

        // Tier (b): opt-in LAN / explicit peer RAM cache.
        var candidates = await CollectCandidateEndpointsAsync(cancellationToken).ConfigureAwait(false);
        foreach (var endpoint in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var bytes = await TryFetchRawEnvelopeAsync(endpoint, cancellationToken).ConfigureAwait(false);
            if (bytes is null || bytes.Length == 0 || bytes.Length > MaxEnvelopeBytes)
            {
                continue;
            }

            var snapshot = VerifyIncomingEnvelopeBytes(bytes, DateTimeOffset.UtcNow, endpoint.ToString());
            if (snapshot is not null && snapshot.Sync.VerifiedRules > currentLocalRules)
            {
                return snapshot;
            }
        }

        return null;
    }

    private void CacheCuratorSignedEnvelopeInMemory(byte[] signedEnvelopeBytes, int rulesCount)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _currentRulesCount = rulesCount;
            _currentEnvelopeBytes = signedEnvelopeBytes;
            _lastSync = null;
            _lastPage = null;
            EnsureListenersStartedLocked();
        }
    }

    /// <summary>
    /// Stateful instance verification with monotonic sequence and timestamp rollback protection.
    /// Used on incoming peer bytes and testable directly in memory.
    /// </summary>
    public VerifiedGraphPeerSnapshot? VerifyIncomingEnvelopeBytes(
        ReadOnlySpan<byte> utf8Json,
        DateTimeOffset nowUtc,
        string peerEndpoint = "peer")
    {
        if (_disposed || string.IsNullOrWhiteSpace(_pinnedPublicKeyDerBase64))
        {
            return null;
        }

        var envelope = TryParseEnvelopeUtf8(utf8Json);
        if (envelope is null)
        {
            return null;
        }

        lock (_gate)
        {
            var snapshot = TryVerifyAndSanitize(
                envelope,
                nowUtc,
                _pinnedPublicKeyDerBase64,
                peerEndpoint,
                _clientVersion,
                _highestAcceptedSequence,
                _highestAcceptedTicks,
                _highestAcceptedMerkle);
            if (snapshot is null)
            {
                return null;
            }

            _highestAcceptedSequence = envelope.SequenceNumber;
            _highestAcceptedTicks = envelope.CreatedUtcTicks;
            _highestAcceptedMerkle = snapshot.MerkleRootHex;
            return snapshot;
        }
    }

    /// <summary>
    /// Builds and cryptographically signs an immutable in-memory manifest + snapshot envelope over
    /// the supplied sanitized threats. Returns null if threats fail whitelist validation.
    /// </summary>
    public static VerifiedGraphPeerEnvelope? CreateSignedEnvelope(
        BlackboxVerifiedSync sync,
        BlackboxGraphPage page,
        ECDsa signingKey,
        string publicKeyDerBase64,
        DateTimeOffset nowUtc,
        long sequenceNumber = 1,
        string minClientVersion = "0.17.0")
    {
        ArgumentNullException.ThrowIfNull(sync);
        ArgumentNullException.ThrowIfNull(page);
        ArgumentNullException.ThrowIfNull(signingKey);

        if (sequenceNumber <= 0 || !Version.TryParse(minClientVersion, out _))
        {
            return null;
        }

        var sanitizedThreats = SanitizeThreats(page.Threats);
        if (sanitizedThreats is null || sanitizedThreats.Count == 0)
        {
            return null;
        }

        var sanitizedTotals = SanitizeCategoryTotals(page.CategoryTotals);
        if (sanitizedTotals is null)
        {
            return null;
        }

        var ordered = OrderCanonical(sanitizedThreats);
        var payloadSha256Hex = ComputeCanonicalPayloadSha256Hex(ordered);
        var merkleRoot = ComputeMerkleRootHex(ordered);
        var createdTicks = nowUtc.UtcTicks;
        var verifiedRules = Math.Max(sync.VerifiedRules, sanitizedThreats.Count);
        var totalThreats = Math.Max(page.Total, sanitizedThreats.Count);

        var signedMessage = BuildSignedTranscript(
            EnvelopeVersion,
            sequenceNumber,
            createdTicks,
            minClientVersion.Trim(),
            verifiedRules,
            totalThreats,
            payloadSha256Hex,
            merkleRoot);
        var signature = signingKey.SignData(signedMessage, HashAlgorithmName.SHA256);

        return new VerifiedGraphPeerEnvelope(
            EnvelopeVersion,
            sequenceNumber,
            createdTicks,
            minClientVersion.Trim(),
            verifiedRules,
            totalThreats,
            payloadSha256Hex,
            merkleRoot,
            publicKeyDerBase64,
            Convert.ToBase64String(signature),
            sanitizedThreats,
            sanitizedTotals);
    }

    /// <summary>
    /// Zero-trust verification of a parsed manifest/snapshot envelope.
    /// Fails closed if <paramref name="pinnedPublicKeyDerBase64"/> is null/empty or does not verify
    /// the ECDSA P-256 signature, if client version is below <c>MinClientVersion</c>, if sequence or
    /// timestamp attempts a rollback, if canonical payload SHA-256 or Merkle root mismatches, or if
    /// any field fails the strict passive-data whitelist.
    /// </summary>
    public static VerifiedGraphPeerSnapshot? TryVerifyAndSanitize(
        VerifiedGraphPeerEnvelope envelope,
        DateTimeOffset nowUtc,
        string? pinnedPublicKeyDerBase64,
        string peerEndpoint = "peer",
        Version? clientVersion = null,
        long minSequenceNumber = 1,
        long minCreatedUtcTicks = 0,
        string? previousMerkleAtMinSequence = null)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        if (string.IsNullOrWhiteSpace(pinnedPublicKeyDerBase64))
        {
            // Never accept an unpinned peer payload ("nikad prihvati jer je peer rekao").
            return null;
        }

        if (envelope.Version != EnvelopeVersion ||
            envelope.SequenceNumber < 1 ||
            envelope.SequenceNumber < minSequenceNumber ||
            envelope.CreatedUtcTicks < minCreatedUtcTicks ||
            envelope.VerifiedRulesCount is <= 0 or > 5_000_000 ||
            envelope.TotalThreats is <= 0 or > 5_000_000 ||
            envelope.Threats is null ||
            envelope.Threats.Count == 0 ||
            envelope.Threats.Count > MaxThreats ||
            envelope.TotalThreats < envelope.Threats.Count)
        {
            return null;
        }

        if (!IsSupportedClientVersion(envelope.MinClientVersion, clientVersion))
        {
            return null;
        }

        if (envelope.CreatedUtcTicks < DateTimeOffset.MinValue.UtcTicks ||
            envelope.CreatedUtcTicks > DateTimeOffset.MaxValue.UtcTicks)
        {
            return null;
        }

        var createdUtc = new DateTimeOffset(envelope.CreatedUtcTicks, TimeSpan.Zero);
        if ((nowUtc - createdUtc).Duration() > FreshnessWindow)
        {
            return null;
        }

        if (!IsValidHexSha256(envelope.PayloadSha256Hex) ||
            !IsValidHexSha256(envelope.MerkleRootHex) ||
            string.IsNullOrWhiteSpace(envelope.PublicKeyDerBase64) ||
            string.IsNullOrWhiteSpace(envelope.SignatureBase64))
        {
            return null;
        }

        var pinnedKey = pinnedPublicKeyDerBase64.Trim();
        if (!FixedTimeStringEquals(envelope.PublicKeyDerBase64.Trim(), pinnedKey))
        {
            return null;
        }

        var sanitizedThreats = SanitizeThreats(envelope.Threats);
        if (sanitizedThreats is null || sanitizedThreats.Count != envelope.Threats.Count)
        {
            return null;
        }

        var sanitizedTotals = SanitizeCategoryTotals(envelope.CategoryTotals);
        if (sanitizedTotals is null)
        {
            return null;
        }

        var ordered = OrderCanonical(sanitizedThreats);
        var expectedPayloadSha256 = ComputeCanonicalPayloadSha256Hex(ordered);
        if (!FixedTimeStringEquals(expectedPayloadSha256, envelope.PayloadSha256Hex.ToUpperInvariant()))
        {
            return null;
        }

        var expectedMerkle = ComputeMerkleRootHex(ordered);
        if (!FixedTimeStringEquals(expectedMerkle, envelope.MerkleRootHex.ToUpperInvariant()))
        {
            return null;
        }

        if (envelope.SequenceNumber == minSequenceNumber &&
            !string.IsNullOrEmpty(previousMerkleAtMinSequence) &&
            !FixedTimeStringEquals(expectedMerkle, previousMerkleAtMinSequence))
        {
            return null;
        }

        if (!VerifyPinnedSignature(envelope, pinnedKey, expectedPayloadSha256, expectedMerkle))
        {
            return null;
        }

        var timestampText = createdUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        var sync = new BlackboxVerifiedSync(
            "synced",
            envelope.TotalThreats,
            envelope.TotalThreats,
            null,
            envelope.TotalThreats,
            envelope.VerifiedRulesCount,
            100.0,
            100.0,
            timestampText,
            new BlackboxLookupState(
                "peer-ram",
                "RAM peer-verified snapshot (no disk write)",
                $"Verified in-memory snapshot from Axiom peer {peerEndpoint} (seq {envelope.SequenceNumber})."),
            "peer-ram",
            $"Loaded {envelope.VerifiedRulesCount:N0} verified rule(s) from peer RAM (cryptographically verified, no disk write).",
            null,
            string.Empty);

        var page = new BlackboxGraphPage(
            sanitizedThreats,
            envelope.TotalThreats,
            Partial: envelope.TotalThreats > sanitizedThreats.Count)
        {
            CategoryTotals = sanitizedTotals,
        };

        return new VerifiedGraphPeerSnapshot(sync, page, envelope.SequenceNumber, expectedMerkle, peerEndpoint);
    }

    /// <summary>
    /// Serializes an envelope to UTF-8 JSON bytes exclusively in RAM via <see cref="Utf8JsonWriter"/>
    /// without reflection.
    /// </summary>
    public static byte[] WriteEnvelopeUtf8(VerifiedGraphPeerEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        using var buffer = new MemoryStream(capacity: 16 * 1024);
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("version"u8, envelope.Version);
            writer.WriteNumber("sequenceNumber"u8, envelope.SequenceNumber);
            writer.WriteNumber("createdUtcTicks"u8, envelope.CreatedUtcTicks);
            writer.WriteString("minClientVersion"u8, envelope.MinClientVersion);
            writer.WriteNumber("verifiedRulesCount"u8, envelope.VerifiedRulesCount);
            writer.WriteNumber("totalThreats"u8, envelope.TotalThreats);
            writer.WriteString("payloadSha256Hex"u8, envelope.PayloadSha256Hex);
            writer.WriteString("merkleRootHex"u8, envelope.MerkleRootHex);
            writer.WriteString("publicKeyDerBase64"u8, envelope.PublicKeyDerBase64);
            writer.WriteString("signatureBase64"u8, envelope.SignatureBase64);

            writer.WriteStartArray("threats"u8);
            foreach (var item in envelope.Threats)
            {
                writer.WriteStartObject();
                writer.WriteString("identifier"u8, item.Identifier);
                writer.WriteString("name"u8, item.Name);
                writer.WriteString("category"u8, item.Category);
                writer.WriteString("severity"u8, item.Severity);
                writer.WriteString("ecosystems"u8, item.Ecosystems);
                writer.WriteString("source"u8, item.Source);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();

            writer.WriteStartObject("categoryTotals"u8);
            foreach (var pair in envelope.CategoryTotals)
            {
                writer.WriteNumber(pair.Key, pair.Value);
            }

            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// Zero-reflection RAM-only parser using <see cref="Utf8JsonReader"/> with <c>MaxDepth = 8</c>.
    /// Immediately rejects any unknown JSON property name in the manifest or threat entries, duplicate
    /// keys, missing required fields, or payloads exceeding <c>4 MiB</c>.
    /// </summary>
    public static VerifiedGraphPeerEnvelope? TryParseEnvelopeUtf8(ReadOnlySpan<byte> utf8Json)
    {
        if (utf8Json.IsEmpty || utf8Json.Length > MaxEnvelopeBytes)
        {
            return null;
        }

        try
        {
            var reader = new Utf8JsonReader(utf8Json, new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 8,
            });

            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return null;
            }

            int? version = null;
            long? sequenceNumber = null;
            long? createdUtcTicks = null;
            string? minClientVersion = null;
            int? verifiedRulesCount = null;
            int? totalThreats = null;
            string? payloadSha256Hex = null;
            string? merkleRootHex = null;
            string? publicKeyDerBase64 = null;
            string? signatureBase64 = null;
            List<BlackboxGraphThreat>? threats = null;
            Dictionary<string, int>? categoryTotals = null;

            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    break;
                }

                if (reader.TokenType != JsonTokenType.PropertyName)
                {
                    return null;
                }

                if (reader.ValueTextEquals("version"u8))
                {
                    if (version is not null || !reader.Read() || reader.TokenType != JsonTokenType.Number || !reader.TryGetInt32(out var v))
                    {
                        return null;
                    }

                    version = v;
                }
                else if (reader.ValueTextEquals("sequenceNumber"u8))
                {
                    if (sequenceNumber is not null || !reader.Read() || reader.TokenType != JsonTokenType.Number || !reader.TryGetInt64(out var s))
                    {
                        return null;
                    }

                    sequenceNumber = s;
                }
                else if (reader.ValueTextEquals("createdUtcTicks"u8))
                {
                    if (createdUtcTicks is not null || !reader.Read() || reader.TokenType != JsonTokenType.Number || !reader.TryGetInt64(out var t))
                    {
                        return null;
                    }

                    createdUtcTicks = t;
                }
                else if (reader.ValueTextEquals("minClientVersion"u8))
                {
                    if (minClientVersion is not null || !ReadRequiredString(ref reader, 32, out var m))
                    {
                        return null;
                    }

                    minClientVersion = m;
                }
                else if (reader.ValueTextEquals("verifiedRulesCount"u8))
                {
                    if (verifiedRulesCount is not null || !reader.Read() || reader.TokenType != JsonTokenType.Number || !reader.TryGetInt32(out var r))
                    {
                        return null;
                    }

                    verifiedRulesCount = r;
                }
                else if (reader.ValueTextEquals("totalThreats"u8))
                {
                    if (totalThreats is not null || !reader.Read() || reader.TokenType != JsonTokenType.Number || !reader.TryGetInt32(out var tt))
                    {
                        return null;
                    }

                    totalThreats = tt;
                }
                else if (reader.ValueTextEquals("payloadSha256Hex"u8))
                {
                    if (payloadSha256Hex is not null || !ReadRequiredString(ref reader, 64, out var p))
                    {
                        return null;
                    }

                    payloadSha256Hex = p;
                }
                else if (reader.ValueTextEquals("merkleRootHex"u8))
                {
                    if (merkleRootHex is not null || !ReadRequiredString(ref reader, 64, out var mk))
                    {
                        return null;
                    }

                    merkleRootHex = mk;
                }
                else if (reader.ValueTextEquals("publicKeyDerBase64"u8))
                {
                    if (publicKeyDerBase64 is not null || !ReadRequiredString(ref reader, 512, out var pk))
                    {
                        return null;
                    }

                    publicKeyDerBase64 = pk;
                }
                else if (reader.ValueTextEquals("signatureBase64"u8))
                {
                    if (signatureBase64 is not null || !ReadRequiredString(ref reader, 512, out var sig))
                    {
                        return null;
                    }

                    signatureBase64 = sig;
                }
                else if (reader.ValueTextEquals("threats"u8))
                {
                    if (threats is not null || !ReadThreatsArray(ref reader, out threats))
                    {
                        return null;
                    }
                }
                else if (reader.ValueTextEquals("categoryTotals"u8))
                {
                    if (categoryTotals is not null || !ReadCategoryTotalsObject(ref reader, out categoryTotals))
                    {
                        return null;
                    }
                }
                else
                {
                    // Unknown field rejection (strict manifest schema).
                    return null;
                }
            }

            if (reader.Read())
            {
                return null;
            }

            if (version is null ||
                sequenceNumber is null ||
                createdUtcTicks is null ||
                minClientVersion is null ||
                verifiedRulesCount is null ||
                totalThreats is null ||
                payloadSha256Hex is null ||
                merkleRootHex is null ||
                publicKeyDerBase64 is null ||
                signatureBase64 is null ||
                threats is null ||
                categoryTotals is null)
            {
                return null;
            }

            return new VerifiedGraphPeerEnvelope(
                version.Value,
                sequenceNumber.Value,
                createdUtcTicks.Value,
                minClientVersion,
                verifiedRulesCount.Value,
                totalThreats.Value,
                payloadSha256Hex,
                merkleRootHex,
                publicKeyDerBase64,
                signatureBase64,
                threats,
                categoryTotals);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static string ComputeMerkleRootHex(IReadOnlyList<BlackboxGraphThreat> threats)
    {
        ArgumentNullException.ThrowIfNull(threats);
        if (threats.Count == 0)
        {
            return string.Empty;
        }

        var ordered = OrderCanonical(threats);
        var level = new List<byte[]>(ordered.Length);
        foreach (var item in ordered)
        {
            level.Add(SHA256.HashData(FormatCanonicalThreatBytes(item)));
        }

        var pairBuffer = new byte[64];
        while (level.Count > 1)
        {
            var next = new List<byte[]>((level.Count + 1) / 2);
            for (var i = 0; i < level.Count; i += 2)
            {
                var left = level[i];
                var right = i + 1 < level.Count ? level[i + 1] : left;
                Buffer.BlockCopy(left, 0, pairBuffer, 0, 32);
                Buffer.BlockCopy(right, 0, pairBuffer, 32, 32);
                next.Add(SHA256.HashData(pairBuffer));
            }

            level = next;
        }

        return Convert.ToHexString(level[0]);
    }

    public static string ComputeCanonicalPayloadSha256Hex(IReadOnlyList<BlackboxGraphThreat> threats)
    {
        ArgumentNullException.ThrowIfNull(threats);
        var ordered = OrderCanonical(threats);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var item in ordered)
        {
            hash.AppendData(FormatCanonicalThreatBytes(item));
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _listenerCts?.Cancel();
            _listenerCts?.Dispose();
            _listenerCts = null;

            try
            {
                _tcpListener?.Stop();
            }
            catch (SocketException)
            {
            }

            _tcpListener = null;

            try
            {
                _udpResponder?.Dispose();
            }
            catch (SocketException)
            {
            }

            _udpResponder = null;
            _currentEnvelopeBytes = null;
            if (_ownsSigningKey)
            {
                _signingKey?.Dispose();
            }
        }
    }

    private void EnsureListenersStartedLocked()
    {
        if (_tcpListener is not null)
        {
            return;
        }

        _listenerCts = new CancellationTokenSource();
        var token = _listenerCts.Token;

        try
        {
            var listener = new TcpListener(_listenAddress, _listenPort);
            listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            listener.Start(backlog: 8);
            _tcpListener = listener;
            var actualPort = ((IPEndPoint)listener.LocalEndpoint).Port;
            Volatile.Write(ref _activeListenPort, actualPort);
            _ = Task.Run(() => RunTcpServerLoopAsync(listener, token), token);

            if (_enableLanBroadcast)
            {
                try
                {
                    var udp = new UdpClient(new IPEndPoint(_listenAddress, actualPort));
                    udp.EnableBroadcast = true;
                    _udpResponder = udp;
                    _ = Task.Run(() => RunUdpDiscoveryLoopAsync(udp, actualPort, token), token);
                }
                catch (SocketException)
                {
                }
            }
        }
        catch (SocketException)
        {
            Volatile.Write(ref _activeListenPort, 0);
        }
    }

    private async Task RunTcpServerLoopAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                var payload = GetFreshEnvelopeBytes();
                if (payload is null || payload.Length == 0)
                {
                    continue;
                }

                client.SendTimeout = (int)NetworkTimeout.TotalMilliseconds;
                client.NoDelay = true;
                using var stream = client.GetStream();
                await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception exception) when (exception is SocketException or IOException or ObjectDisposedException)
            {
            }
        }
    }

    private async Task RunUdpDiscoveryLoopAsync(UdpClient udp, int tcpPort, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var received = await udp.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                var message = Encoding.UTF8.GetString(received.Buffer);
                if (!string.Equals(message, DiscoveryRequest, StringComparison.Ordinal))
                {
                    continue;
                }

                int rulesCount;
                lock (_gate)
                {
                    rulesCount = _currentRulesCount;
                }

                if (rulesCount <= 0)
                {
                    continue;
                }

                var offer = Encoding.UTF8.GetBytes($"{DiscoveryResponsePrefix}{tcpPort}:{rulesCount}");
                await udp.SendAsync(offer, offer.Length, received.RemoteEndPoint).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception exception) when (exception is SocketException or IOException or ObjectDisposedException)
            {
            }
        }
    }

    private byte[]? GetFreshEnvelopeBytes()
    {
        lock (_gate)
        {
            if (_disposed || _currentEnvelopeBytes is null)
            {
                return null;
            }

            var now = DateTimeOffset.UtcNow;
            if (now - _lastSignedUtc > ReSignInterval &&
                _lastSync is not null &&
                _lastPage is not null &&
                _signingKey is not null)
            {
                var nextSequence = _publishSequence + 1;
                var refreshed = CreateSignedEnvelope(
                    _lastSync,
                    _lastPage,
                    _signingKey,
                    _signingPublicKeyDerBase64,
                    now,
                    nextSequence,
                    _minClientVersion);
                if (refreshed is not null)
                {
                    var bytes = WriteEnvelopeUtf8(refreshed);
                    if (bytes.Length <= MaxEnvelopeBytes)
                    {
                        _publishSequence = nextSequence;
                        _currentEnvelopeBytes = bytes;
                        _lastSignedUtc = now;
                    }
                }
            }

            return _currentEnvelopeBytes;
        }
    }

    private async Task<List<IPEndPoint>> CollectCandidateEndpointsAsync(CancellationToken cancellationToken)
    {
        var results = new List<IPEndPoint>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        void AddEndpoint(IPAddress address, int port)
        {
            if (port is <= 0 or > 65535)
            {
                return;
            }

            var endpoint = new IPEndPoint(address, port);
            if (seen.Add(endpoint.ToString()))
            {
                results.Add(endpoint);
            }
        }

        if (_explicitPeersOverride is not null)
        {
            foreach (var raw in _explicitPeersOverride)
            {
                if (TryParseEndpoint(raw, out var ep))
                {
                    AddEndpoint(ep.Address, ep.Port);
                }
            }

            return results;
        }

        var envPeers = ReadEnv("AXIOM_GRAPH_PEERS");
        if (!string.IsNullOrWhiteSpace(envPeers))
        {
            foreach (var raw in envPeers.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (TryParseEndpoint(raw, out var ep))
                {
                    AddEndpoint(ep.Address, ep.Port);
                }
            }
        }

        if (_enableLanBroadcast)
        {
            foreach (var discovered in await DiscoverLanPeersAsync(cancellationToken).ConfigureAwait(false))
            {
                AddEndpoint(discovered.Address, discovered.Port);
            }
        }

        return results;
    }

    private static async Task<List<IPEndPoint>> DiscoverLanPeersAsync(CancellationToken cancellationToken)
    {
        var discovered = new List<IPEndPoint>();
        try
        {
            using var udp = new UdpClient();
            udp.EnableBroadcast = true;
            var probe = Encoding.UTF8.GetBytes(DiscoveryRequest);
            await udp.SendAsync(probe, probe.Length, new IPEndPoint(IPAddress.Broadcast, DefaultPort)).ConfigureAwait(false);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromMilliseconds(350));
            while (!timeoutCts.IsCancellationRequested && discovered.Count < 8)
            {
                var response = await udp.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
                var text = Encoding.UTF8.GetString(response.Buffer);
                if (!text.StartsWith(DiscoveryResponsePrefix, StringComparison.Ordinal))
                {
                    continue;
                }

                var parts = text[DiscoveryResponsePrefix.Length..].Split(':');
                if (parts.Length >= 1 &&
                    int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var port) &&
                    port is > 0 and <= 65535)
                {
                    discovered.Add(new IPEndPoint(response.RemoteEndPoint.Address, port));
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception exception) when (exception is SocketException or IOException or ObjectDisposedException)
        {
        }

        return discovered;
    }

    private static async Task<byte[]?> TryFetchRawSnapshotFromUriAsync(Uri uri, CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(NetworkTimeout);

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            using var response = await SharedSnapshotHttpClient
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeoutCts.Token)
                .ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK ||
                response.Content.Headers.ContentLength is > MaxEnvelopeBytes)
            {
                return null;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(timeoutCts.Token).ConfigureAwait(false);
            return await ReadBoundedMemoryStreamAsync(stream, timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException)
        {
            return null;
        }
    }

    private static async Task<byte[]?> TryFetchRawEnvelopeAsync(IPEndPoint endpoint, CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(NetworkTimeout);

        try
        {
            using var client = new TcpClient(endpoint.AddressFamily);
            await client.ConnectAsync(endpoint.Address, endpoint.Port, timeoutCts.Token).ConfigureAwait(false);
            using var stream = client.GetStream();
            return await ReadBoundedMemoryStreamAsync(stream, timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (Exception exception) when (exception is SocketException or IOException or ObjectDisposedException)
        {
            return null;
        }
    }

    private static async Task<byte[]?> ReadBoundedMemoryStreamAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream(capacity: 32 * 1024);
        var chunk = new byte[16 * 1024];

        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (buffer.Length + read > MaxEnvelopeBytes)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    private static bool ReadRequiredString(ref Utf8JsonReader reader, int maxLength, out string value)
    {
        value = string.Empty;
        if (!reader.Read() || reader.TokenType != JsonTokenType.String)
        {
            return false;
        }

        var text = reader.GetString();
        if (text is null || text.Length > maxLength)
        {
            return false;
        }

        value = text;
        return true;
    }

    private static bool ReadThreatsArray(ref Utf8JsonReader reader, out List<BlackboxGraphThreat> threats)
    {
        threats = [];
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartArray)
        {
            return false;
        }

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndArray)
            {
                return true;
            }

            if (reader.TokenType != JsonTokenType.StartObject || threats.Count >= MaxThreats)
            {
                return false;
            }

            string? identifier = null;
            string? name = null;
            string? category = null;
            string? severity = null;
            string? ecosystems = null;
            string? source = null;

            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    break;
                }

                if (reader.TokenType != JsonTokenType.PropertyName)
                {
                    return false;
                }

                if (reader.ValueTextEquals("identifier"u8))
                {
                    if (identifier is not null || !ReadRequiredString(ref reader, MaxTextLength, out var v))
                    {
                        return false;
                    }

                    identifier = v;
                }
                else if (reader.ValueTextEquals("name"u8))
                {
                    if (name is not null || !ReadRequiredString(ref reader, MaxTextLength, out var v))
                    {
                        return false;
                    }

                    name = v;
                }
                else if (reader.ValueTextEquals("category"u8))
                {
                    if (category is not null || !ReadRequiredString(ref reader, 32, out var v))
                    {
                        return false;
                    }

                    category = v;
                }
                else if (reader.ValueTextEquals("severity"u8))
                {
                    if (severity is not null || !ReadRequiredString(ref reader, 32, out var v))
                    {
                        return false;
                    }

                    severity = v;
                }
                else if (reader.ValueTextEquals("ecosystems"u8))
                {
                    if (ecosystems is not null || !ReadRequiredString(ref reader, MaxTextLength, out var v))
                    {
                        return false;
                    }

                    ecosystems = v;
                }
                else if (reader.ValueTextEquals("source"u8))
                {
                    if (source is not null || !ReadRequiredString(ref reader, 32, out var v))
                    {
                        return false;
                    }

                    source = v;
                }
                else
                {
                    // Unknown threat field rejection.
                    return false;
                }
            }

            if (identifier is null || name is null || category is null || severity is null || ecosystems is null || source is null)
            {
                return false;
            }

            threats.Add(new BlackboxGraphThreat(identifier, name, category, severity, ecosystems, source));
        }

        return false;
    }

    private static bool ReadCategoryTotalsObject(ref Utf8JsonReader reader, out Dictionary<string, int> totals)
    {
        totals = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            return false;
        }

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                return true;
            }

            if (reader.TokenType != JsonTokenType.PropertyName || totals.Count >= 16)
            {
                return false;
            }

            var key = (reader.GetString() ?? string.Empty).Trim().ToLowerInvariant();
            if (!AllowedCategories.Contains(key) || totals.ContainsKey(key))
            {
                return false;
            }

            if (!reader.Read() || reader.TokenType != JsonTokenType.Number || !reader.TryGetInt32(out var count) || count < 0 || count > 5_000_000)
            {
                return false;
            }

            totals[key] = count;
        }

        return false;
    }

    private static bool TryParseEndpoint(string raw, out IPEndPoint endpoint)
    {
        if (IPEndPoint.TryParse(raw.Trim(), out var parsed))
        {
            endpoint = parsed.Port == 0
                ? new IPEndPoint(parsed.Address, DefaultPort)
                : parsed;
            return true;
        }

        if (IPAddress.TryParse(raw.Trim(), out var ip))
        {
            endpoint = new IPEndPoint(ip, DefaultPort);
            return true;
        }

        endpoint = new IPEndPoint(IPAddress.Loopback, DefaultPort);
        return false;
    }

    private static string? ReadEnv(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    private static Version NormalizeVersion(Version version) =>
        new(Math.Max(0, version.Major), Math.Max(0, version.Minor), Math.Max(0, version.Build));

    private static bool IsSupportedClientVersion(string? minClientVersion, Version? clientVersionOverride)
    {
        if (string.IsNullOrWhiteSpace(minClientVersion) ||
            !Version.TryParse(minClientVersion.Trim(), out var requiredRaw))
        {
            return false;
        }

        var currentRaw = clientVersionOverride ??
                         typeof(VerifiedGraphPeerRelay).Assembly.GetName().Version ??
                         new Version(0, 17, 0);
        return NormalizeVersion(currentRaw) >= NormalizeVersion(requiredRaw);
    }

    private static BlackboxGraphThreat[] OrderCanonical(IReadOnlyList<BlackboxGraphThreat> threats) =>
        threats
            .OrderBy(t => t.Identifier, StringComparer.Ordinal)
            .ThenBy(t => t.Category, StringComparer.Ordinal)
            .ThenBy(t => t.Severity, StringComparer.Ordinal)
            .ThenBy(t => t.Ecosystems, StringComparer.Ordinal)
            .ThenBy(t => t.Source, StringComparer.Ordinal)
            .ToArray();

    private static byte[] FormatCanonicalThreatBytes(BlackboxGraphThreat item) =>
        Encoding.UTF8.GetBytes(
            $"{item.Identifier}\x1f{item.Name}\x1f{item.Category}\x1f{item.Severity}\x1f{item.Ecosystems}\x1f{item.Source}\n");

    private static byte[] BuildSignedTranscript(
        int version,
        long sequenceNumber,
        long createdUtcTicks,
        string minClientVersion,
        int verifiedRulesCount,
        int totalThreats,
        string payloadSha256Hex,
        string merkleRootHex) =>
        Encoding.UTF8.GetBytes(
            $"Axiom-VerifiedGraph-v1|{version}|{sequenceNumber}|{createdUtcTicks}|{minClientVersion}|{verifiedRulesCount}|{totalThreats}|{payloadSha256Hex}|{merkleRootHex}");

    private static bool VerifyPinnedSignature(
        VerifiedGraphPeerEnvelope envelope,
        string pinnedKeyBase64,
        string expectedPayloadSha256,
        string expectedMerkle)
    {
        try
        {
            var publicKeyBytes = Convert.FromBase64String(pinnedKeyBase64);
            var signatureBytes = Convert.FromBase64String(envelope.SignatureBase64);
            if (publicKeyBytes.Length > 1024 || signatureBytes.Length > 512)
            {
                return false;
            }

            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKeyBytes, out var read);
            if (read != publicKeyBytes.Length)
            {
                return false;
            }

            var transcript = BuildSignedTranscript(
                envelope.Version,
                envelope.SequenceNumber,
                envelope.CreatedUtcTicks,
                envelope.MinClientVersion.Trim(),
                envelope.VerifiedRulesCount,
                envelope.TotalThreats,
                expectedPayloadSha256,
                expectedMerkle);
            return key.VerifyData(transcript, signatureBytes, HashAlgorithmName.SHA256);
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException)
        {
            return false;
        }
    }

    private static List<BlackboxGraphThreat>? SanitizeThreats(IReadOnlyList<BlackboxGraphThreat> source)
    {
        var result = new List<BlackboxGraphThreat>(Math.Min(source.Count, MaxThreats));
        foreach (var item in source.Take(MaxThreats))
        {
            if (item is null ||
                !IsSafeDisplayText(item.Name) ||
                !IsSafeEcosystemsText(item.Ecosystems))
            {
                return null;
            }

            var category = (item.Category ?? string.Empty).Trim().ToLowerInvariant();
            if (!AllowedCategories.Contains(category))
            {
                return null;
            }

            if (!IsSafeIdentifier(item.Identifier, category))
            {
                return null;
            }

            var severity = string.IsNullOrWhiteSpace(item.Severity)
                ? "unknown"
                : item.Severity.Trim().ToLowerInvariant();
            if (!AllowedSeverities.Contains(severity))
            {
                return null;
            }

            var sourceLabel = string.IsNullOrWhiteSpace(item.Source)
                ? "public"
                : item.Source.Trim().ToLowerInvariant();
            if (!AllowedSources.Contains(sourceLabel))
            {
                return null;
            }

            result.Add(new BlackboxGraphThreat(
                item.Identifier.Trim(),
                (item.Name ?? string.Empty).Trim(),
                category,
                severity,
                (item.Ecosystems ?? string.Empty).Trim(),
                sourceLabel));
        }

        return result;
    }

    private static Dictionary<string, int>? SanitizeCategoryTotals(IReadOnlyDictionary<string, int>? totals)
    {
        var sanitized = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (totals is null)
        {
            return sanitized;
        }

        foreach (var pair in totals)
        {
            var key = (pair.Key ?? string.Empty).Trim().ToLowerInvariant();
            if (!AllowedCategories.Contains(key) || pair.Value is < 0 or > 5_000_000)
            {
                return null;
            }

            sanitized[key] = pair.Value;
        }

        return sanitized;
    }

    private static bool IsSafeIdentifier(string? value, string category)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (trimmed.Length is < 1 or > MaxTextLength ||
            trimmed.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var ch in trimmed)
        {
            if (ch is < '\x21' or > '\x7E' ||
                ch is '\\' or ';' or '|' or '&' or '`' or '$' or '<' or '>' or '"' or '\'')
            {
                return false;
            }
        }

        if (category == "ioc" && !trimmed.Contains(':', StringComparison.Ordinal))
        {
            return IsValidHexSha256(trimmed) ||
                   IPAddress.TryParse(trimmed, out _) ||
                   DomainRegex().IsMatch(trimmed);
        }

        return IsValidHexSha256(trimmed) ||
               IPAddress.TryParse(trimmed, out _) ||
               DomainRegex().IsMatch(trimmed) ||
               SafeTokenRegex().IsMatch(trimmed) ||
               (trimmed.StartsWith('@') && SafeTokenRegex().IsMatch(trimmed[1..]));
    }

    private static bool IsSafeDisplayText(string? value)
    {
        if (value is null)
        {
            return true;
        }

        if (value.Length > MaxTextLength)
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (ch < '\x20' || ch == '\x7F')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsSafeEcosystemsText(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        if (value.Length > MaxTextLength)
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (!(ch is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or
                    '.' or '_' or ',' or ':' or '/' or '-' or ' '))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsValidHexSha256(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length != 64)
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (!(ch is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F')))
            {
                return false;
            }
        }

        return true;
    }

    private static bool FixedTimeStringEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length &&
               CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }
}
