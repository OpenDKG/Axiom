// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Axiom.Contracts.Blackbox;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class VerifiedGraphPeerRelayTests
{
    private static BlackboxVerifiedSync SampleSync(int verifiedRules = 120) =>
        new(
            "synced",
            verifiedRules,
            verifiedRules,
            null,
            verifiedRules,
            verifiedRules,
            100.0,
            100.0,
            "2026-11-14 01:00:00",
            new BlackboxLookupState("ok", "Live from graph", "Connected"),
            "synced",
            $"{verifiedRules} rules compiled",
            null,
            string.Empty);

    private static BlackboxGraphPage SamplePage(string identifier = "malicious.example", string category = "ioc") =>
        new(
            [
                new BlackboxGraphThreat(identifier, "Blocked Indicator", category, "high", "npm", "verified"),
                new BlackboxGraphThreat("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "Bad Binary", "ioc", "critical", string.Empty, "public"),
            ],
            120,
            Partial: true)
        {
            CategoryTotals = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                ["ioc"] = 120,
            },
        };

    [Fact]
    public async Task Valid_pinned_key_signed_snapshot_round_trips_in_memory_between_peers()
    {
        using var curatorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pinnedPublicKey = Convert.ToBase64String(curatorKey.ExportSubjectPublicKeyInfo());

        using var publisher = new VerifiedGraphPeerRelay(
            listenPort: 0,
            listenAddress: IPAddress.Loopback,
            pinnedPublicKeyDerBase64: pinnedPublicKey,
            curatorSigningKey: curatorKey,
            enableLanBroadcast: false,
            optInOverride: true,
            clientVersion: new Version(0, 17, 0),
            minClientVersion: "0.17.0");

        Assert.True(publisher.PublishInMemory(SampleSync(120), SamplePage()));
        Assert.True(publisher.ListeningPort > 0);

        using var client = new VerifiedGraphPeerRelay(
            listenPort: 0,
            listenAddress: IPAddress.Loopback,
            pinnedPublicKeyDerBase64: pinnedPublicKey,
            explicitPeersOverride: [$"127.0.0.1:{publisher.ListeningPort}"],
            enableLanBroadcast: false,
            optInOverride: true,
            clientVersion: new Version(0, 17, 0));

        var loaded = await client.TryFetchFromPeersAsync(currentLocalRules: 0, CancellationToken.None);

        Assert.NotNull(loaded);
        Assert.Equal(120, loaded.Sync.VerifiedRules);
        Assert.Equal("peer-ram", loaded.Sync.Lookups.State);
        Assert.Equal(2, loaded.Graph.Threats.Count);
        Assert.Equal("malicious.example", loaded.Graph.Threats[0].Identifier);
        Assert.Equal(1, loaded.SequenceNumber);
    }

    [Fact]
    public void Unpinned_or_wrong_curator_key_is_rejected_and_falls_back()
    {
        using var peerSelfKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var trustedCuratorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var peerKeyBase64 = Convert.ToBase64String(peerSelfKey.ExportSubjectPublicKeyInfo());
        var trustedKeyBase64 = Convert.ToBase64String(trustedCuratorKey.ExportSubjectPublicKeyInfo());
        var now = DateTimeOffset.UtcNow;

        var selfSigned = VerifiedGraphPeerRelay.CreateSignedEnvelope(
            SampleSync(),
            SamplePage(),
            peerSelfKey,
            peerKeyBase64,
            now);
        Assert.NotNull(selfSigned);

        // Null/empty pinned key fails closed instead of trusting a peer-supplied key.
        Assert.Null(VerifiedGraphPeerRelay.TryVerifyAndSanitize(selfSigned, now, pinnedPublicKeyDerBase64: null));
        Assert.Null(VerifiedGraphPeerRelay.TryVerifyAndSanitize(selfSigned, now, pinnedPublicKeyDerBase64: string.Empty));

        // Wrong curator key also fails closed.
        Assert.Null(VerifiedGraphPeerRelay.TryVerifyAndSanitize(selfSigned, now, trustedKeyBase64));
    }

    [Fact]
    public void Unknown_json_field_in_manifest_or_threat_is_rejected_by_utf8_reader()
    {
        using var curatorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pinnedKey = Convert.ToBase64String(curatorKey.ExportSubjectPublicKeyInfo());
        var now = DateTimeOffset.UtcNow;

        var envelope = VerifiedGraphPeerRelay.CreateSignedEnvelope(
            SampleSync(),
            SamplePage(),
            curatorKey,
            pinnedKey,
            now)!;
        var validJson = Encoding.UTF8.GetString(VerifiedGraphPeerRelay.WriteEnvelopeUtf8(envelope));

        var withUnknownManifestField = validJson.Replace(
            "\"version\":1",
            "\"version\":1,\"execCmd\":\"calc.exe\"",
            StringComparison.Ordinal);
        Assert.Null(VerifiedGraphPeerRelay.TryParseEnvelopeUtf8(Encoding.UTF8.GetBytes(withUnknownManifestField)));

        var withUnknownThreatField = validJson.Replace(
            "\"source\":\"verified\"",
            "\"source\":\"verified\",\"extraScript\":\"powershell\"",
            StringComparison.Ordinal);
        Assert.Null(VerifiedGraphPeerRelay.TryParseEnvelopeUtf8(Encoding.UTF8.GetBytes(withUnknownThreatField)));
    }

    [Fact]
    public void Rollback_to_older_sequence_or_timestamp_is_rejected()
    {
        using var curatorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pinnedKey = Convert.ToBase64String(curatorKey.ExportSubjectPublicKeyInfo());
        var t1 = DateTimeOffset.UtcNow.AddMinutes(-2);
        var t2 = t1.AddMinutes(1);

        var envSeq2 = VerifiedGraphPeerRelay.CreateSignedEnvelope(
            SampleSync(200),
            SamplePage(),
            curatorKey,
            pinnedKey,
            t2,
            sequenceNumber: 2)!;
        var envSeq1 = VerifiedGraphPeerRelay.CreateSignedEnvelope(
            SampleSync(150),
            SamplePage(),
            curatorKey,
            pinnedKey,
            t1,
            sequenceNumber: 1)!;

        using var receiver = new VerifiedGraphPeerRelay(
            pinnedPublicKeyDerBase64: pinnedKey,
            optInOverride: true,
            clientVersion: new Version(0, 17, 0));

        var accepted = receiver.VerifyIncomingEnvelopeBytes(
            VerifiedGraphPeerRelay.WriteEnvelopeUtf8(envSeq2),
            t2.AddSeconds(5));
        Assert.NotNull(accepted);

        // Attempt rollback to sequence 1 / older timestamp must be rejected.
        var rollback = receiver.VerifyIncomingEnvelopeBytes(
            VerifiedGraphPeerRelay.WriteEnvelopeUtf8(envSeq1),
            t2.AddSeconds(10));
        Assert.Null(rollback);

        // Client version older than MinClientVersion is also rejected.
        var newerMinClient = VerifiedGraphPeerRelay.CreateSignedEnvelope(
            SampleSync(250),
            SamplePage(),
            curatorKey,
            pinnedKey,
            t2,
            sequenceNumber: 3,
            minClientVersion: "9.9.9")!;
        Assert.Null(VerifiedGraphPeerRelay.TryVerifyAndSanitize(
            newerMinClient,
            t2.AddSeconds(5),
            pinnedKey,
            clientVersion: new Version(0, 17, 0)));
    }

    [Fact]
    public void Tampered_payload_or_invalid_merkle_root_is_rejected()
    {
        using var curatorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pinnedKey = Convert.ToBase64String(curatorKey.ExportSubjectPublicKeyInfo());
        var now = DateTimeOffset.UtcNow;

        var envelope = VerifiedGraphPeerRelay.CreateSignedEnvelope(
            SampleSync(),
            SamplePage(),
            curatorKey,
            pinnedKey,
            now)!;

        var tamperedThreats = new List<BlackboxGraphThreat>(envelope.Threats)
        {
            [0] = envelope.Threats[0] with { Identifier = "tampered.example" },
        };
        var tamperedEnvelope = envelope with { Threats = tamperedThreats };

        Assert.Null(VerifiedGraphPeerRelay.TryVerifyAndSanitize(tamperedEnvelope, now, pinnedKey));
    }

    [Theory]
    [InlineData("../../evil.exe", "ioc")]
    [InlineData("evil.example; rm -rf /", "ioc")]
    [InlineData("C:\\Windows\\System32\\cmd.exe", "ioc")]
    [InlineData("malicious.example", "executable-payload")]
    public void Malicious_identifier_with_shell_or_path_traversal_is_rejected(string badIdentifier, string category)
    {
        using var curatorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pinnedKey = Convert.ToBase64String(curatorKey.ExportSubjectPublicKeyInfo());
        var now = DateTimeOffset.UtcNow;

        var maliciousEnvelope = VerifiedGraphPeerRelay.CreateSignedEnvelope(
            SampleSync(),
            SamplePage(badIdentifier, category),
            curatorKey,
            pinnedKey,
            now);

        Assert.Null(maliciousEnvelope);
    }

    [Fact]
    public async Task SnapshotEndpoint_FetchesSignedManifestOverHttpInRam_AndRejectsNonHttpsRemoteUri()
    {
        Assert.Null(VerifiedGraphPeerRelay.TryParseAllowedSnapshotUri("http://example.com/snapshot.json"));
        Assert.Null(VerifiedGraphPeerRelay.TryParseAllowedSnapshotUri("https://user:pass@cdn.example/snapshot.json"));
        Assert.NotNull(VerifiedGraphPeerRelay.TryParseAllowedSnapshotUri("https://cdn.example/snapshot.json"));
        Assert.NotNull(VerifiedGraphPeerRelay.TryParseAllowedSnapshotUri("http://127.0.0.1:8080/snapshot.json"));

        using var curatorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pinnedKey = Convert.ToBase64String(curatorKey.ExportSubjectPublicKeyInfo());
        var now = DateTimeOffset.UtcNow;

        var signedEnvelope = VerifiedGraphPeerRelay.CreateSignedEnvelope(
            SampleSync(240),
            SamplePage("cdn-threat.example", "ioc"),
            curatorKey,
            pinnedKey,
            now,
            sequenceNumber: 7)!;
        var bodyBytes = VerifiedGraphPeerRelay.WriteEnvelopeUtf8(signedEnvelope);

        using var server = new TcpListener(IPAddress.Loopback, 0);
        server.Start();
        var port = ((IPEndPoint)server.LocalEndpoint).Port;

        var serveTask = Task.Run(async () =>
        {
            using var client = await server.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            var requestBuf = new byte[1024];
            _ = await stream.ReadAsync(requestBuf);
            var headers = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {bodyBytes.Length}\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(headers);
            await stream.WriteAsync(bodyBytes);
            await stream.FlushAsync();
        });

        using var relay = new VerifiedGraphPeerRelay(
            listenPort: 0,
            listenAddress: IPAddress.Loopback,
            pinnedPublicKeyDerBase64: pinnedKey,
            enableLanBroadcast: false,
            optInOverride: true,
            clientVersion: new Version(0, 17, 0),
            snapshotEndpointOverride: new Uri($"http://127.0.0.1:{port}/snapshot.json"));

        var loaded = await relay.TryFetchFromPeersAsync(currentLocalRules: 0, CancellationToken.None);
        await serveTask;

        Assert.NotNull(loaded);
        Assert.Equal(240, loaded.Sync.VerifiedRules);
        Assert.Equal(7, loaded.SequenceNumber);
        Assert.Equal("cdn-threat.example", loaded.Graph.Threats[0].Identifier);
        Assert.Equal($"http://127.0.0.1:{port}", loaded.PeerEndpoint);
    }
}
