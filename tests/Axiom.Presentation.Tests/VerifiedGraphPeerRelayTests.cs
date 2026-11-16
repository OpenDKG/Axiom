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

    [Fact]
    public void TierA_SnapshotFreshnessWindow_AcceptsSixDayOldCuratorSnapshot_AndRejectsFutureOrExpired()
    {
        using var curatorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pinnedKey = Convert.ToBase64String(curatorKey.ExportSubjectPublicKeyInfo());
        var now = DateTimeOffset.UtcNow;

        var sixDaysOld = VerifiedGraphPeerRelay.CreateSignedEnvelope(
            SampleSync(300),
            SamplePage(),
            curatorKey,
            pinnedKey,
            now.AddDays(-6),
            sequenceNumber: 1)!;

        // Tier (b) LAN rejects 6-day-old snapshot (> 15 min window), while Tier (a) accepts within 7 days.
        Assert.Null(VerifiedGraphPeerRelay.TryVerifyAndSanitize(sixDaysOld, now, pinnedKey));
        var tierASnapshot = VerifiedGraphPeerRelay.TryVerifyAndSanitize(
            sixDaysOld,
            now,
            pinnedKey,
            maxAge: VerifiedGraphPeerRelay.SnapshotFreshnessWindow);
        Assert.NotNull(tierASnapshot);

        // Expired (> 7 days) or future-dated (> 15 min) curator snapshots must still fail closed.
        var eightDaysOld = VerifiedGraphPeerRelay.CreateSignedEnvelope(
            SampleSync(300),
            SamplePage(),
            curatorKey,
            pinnedKey,
            now.AddDays(-8),
            sequenceNumber: 2)!;
        Assert.Null(VerifiedGraphPeerRelay.TryVerifyAndSanitize(
            eightDaysOld,
            now,
            pinnedKey,
            maxAge: VerifiedGraphPeerRelay.SnapshotFreshnessWindow));

        var farFuture = VerifiedGraphPeerRelay.CreateSignedEnvelope(
            SampleSync(300),
            SamplePage(),
            curatorKey,
            pinnedKey,
            now.AddHours(1),
            sequenceNumber: 3)!;
        Assert.Null(VerifiedGraphPeerRelay.TryVerifyAndSanitize(
            farFuture,
            now,
            pinnedKey,
            maxAge: VerifiedGraphPeerRelay.SnapshotFreshnessWindow));
    }

    [Fact]
    public void TierA_SnapshotOnlyConfig_DoesNotEnablePeerRelayOrOpenListeners()
    {
        using var curatorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pinnedKey = Convert.ToBase64String(curatorKey.ExportSubjectPublicKeyInfo());

        using var relay = new VerifiedGraphPeerRelay(
            pinnedPublicKeyDerBase64: pinnedKey,
            snapshotEndpointOverride: new Uri(VerifiedGraphPeerRelay.DefaultSnapshotUrl));

        Assert.True(relay.IsEnabled);
        Assert.True(relay.IsSnapshotBootstrapEnabled);
        Assert.False(relay.IsPeerRelayEnabled);
        Assert.False(relay.PublishInMemory(SampleSync(100), SamplePage()));
        Assert.Equal(0, relay.ListeningPort);
    }

    [Fact]
    public void RedirectPolicy_AllowsHttpsToHttps_AndRejectsDowngradeUserInfoOrPrivateIps()
    {
        var initialHttps = new Uri(VerifiedGraphPeerRelay.DefaultSnapshotUrl);

        Assert.True(VerifiedGraphPeerRelay.IsAllowedRedirectTarget(
            initialHttps,
            new Uri("https://objects.githubusercontent.com/github-production-release-asset/12345")));
        Assert.False(VerifiedGraphPeerRelay.IsAllowedRedirectTarget(
            initialHttps,
            new Uri("http://objects.githubusercontent.com/insecure")));
        Assert.False(VerifiedGraphPeerRelay.IsAllowedRedirectTarget(
            initialHttps,
            new Uri("https://127.0.0.1:9700/status")));
        Assert.False(VerifiedGraphPeerRelay.IsAllowedRedirectTarget(
            initialHttps,
            new Uri("https://localhost/internal")));
        Assert.False(VerifiedGraphPeerRelay.IsAllowedRedirectTarget(
            initialHttps,
            new Uri("https://169.254.10.20/internal")));
        Assert.False(VerifiedGraphPeerRelay.IsAllowedRedirectTarget(
            initialHttps,
            new Uri("https://192.168.1.10/admin")));
        Assert.False(VerifiedGraphPeerRelay.IsAllowedRedirectTarget(
            initialHttps,
            new Uri("https://user:pass@cdn.example/snapshot.json")));
    }

    [Fact]
    public async Task SnapshotEndpoint_FollowsSafeLoopbackRedirect_AndCachesVerifiedSnapshotInRam()
    {
        using var curatorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pinnedKey = Convert.ToBase64String(curatorKey.ExportSubjectPublicKeyInfo());
        var now = DateTimeOffset.UtcNow;

        var signedEnvelope = VerifiedGraphPeerRelay.CreateSignedEnvelope(
            SampleSync(310),
            SamplePage("release-asset.example", "ioc"),
            curatorKey,
            pinnedKey,
            now.AddHours(-12),
            sequenceNumber: 12)!;
        var bodyBytes = VerifiedGraphPeerRelay.WriteEnvelopeUtf8(signedEnvelope);

        using var targetServer = new TcpListener(IPAddress.Loopback, 0);
        targetServer.Start();
        var targetPort = ((IPEndPoint)targetServer.LocalEndpoint).Port;

        using var redirectServer = new TcpListener(IPAddress.Loopback, 0);
        redirectServer.Start();
        var redirectPort = ((IPEndPoint)redirectServer.LocalEndpoint).Port;

        var httpHits = 0;
        var redirectTask = Task.Run(async () =>
        {
            using var client = await redirectServer.AcceptTcpClientAsync();
            Interlocked.Increment(ref httpHits);
            using var stream = client.GetStream();
            _ = await stream.ReadAsync(new byte[1024]);
            var response = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{targetPort}/cdn/verified-graph-snapshot.json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(response);
            await stream.FlushAsync();
        });

        var targetTask = Task.Run(async () =>
        {
            using var client = await targetServer.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            _ = await stream.ReadAsync(new byte[1024]);
            var headers = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {bodyBytes.Length}\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(headers);
            await stream.WriteAsync(bodyBytes);
            await stream.FlushAsync();
        });

        using var relay = new VerifiedGraphPeerRelay(
            pinnedPublicKeyDerBase64: pinnedKey,
            clientVersion: new Version(0, 54, 0),
            snapshotEndpointOverride: new Uri($"http://127.0.0.1:{redirectPort}/releases/download/verified-graph-latest/verified-graph-snapshot.json"));

        var first = await relay.TryFetchFromPeersAsync(currentLocalRules: 0, CancellationToken.None);
        await Task.WhenAll(redirectTask, targetTask);

        // Second call hits RAM cache cleanly without making another HTTP request.
        var second = await relay.TryFetchFromPeersAsync(currentLocalRules: 0, CancellationToken.None);

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.Equal(310, first.Sync.VerifiedRules);
        Assert.Equal(12, first.SequenceNumber);
        Assert.Equal(1, Volatile.Read(ref httpHits));
        Assert.Equal("release-asset.example", second.Graph.Threats[0].Identifier);

        // Once local DKG exceeds snapshot rules, peer relay defers cleanly to local DKG.
        Assert.Null(await relay.TryFetchFromPeersAsync(currentLocalRules: 500, CancellationToken.None));
    }

    [Fact]
    public void RealBlackboxFormats_DependencyWildcardsInjectionAndSkillIds_AreAccepted()
    {
        using var curatorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pinnedKey = Convert.ToBase64String(curatorKey.ExportSubjectPublicKeyInfo());
        var now = DateTimeOffset.UtcNow;

        var page = new BlackboxGraphPage(
            [
                new BlackboxGraphThreat("injection:0250b88aa25cd7f84ac8735a", "Instruction override", "injection", "high", string.Empty, "public"),
                new BlackboxGraphThreat("skill:0a0f825ecd735dec32e0589e", "Unrestricted shell-execution MCP", "skill", "critical", string.Empty, "public"),
                new BlackboxGraphThreat("dep:npm:@zalastax/nolb-react-rk@*", "Malicious code in @zalastax/nolb-react-rk (npm)", "dependency", "high", "npm", "public"),
                new BlackboxGraphThreat("dep:pypi:mcgrand@*", "Malicious code in mcgrand (PyPI)", "dependency", "medium", "pypi", "public"),
            ],
            1306960,
            Partial: true)
        {
            CategoryTotals = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                ["injection"] = 103,
                ["skill"] = 32,
                ["dependency"] = 252860,
                ["ioc"] = 1053965,
            },
        };

        var envelope = VerifiedGraphPeerRelay.CreateSignedEnvelope(
            SampleSync(1306960),
            page,
            curatorKey,
            pinnedKey,
            now,
            sequenceNumber: 1,
            minClientVersion: "0.54.0");

        Assert.NotNull(envelope);
        var verified = VerifiedGraphPeerRelay.TryVerifyAndSanitize(
            envelope,
            now,
            pinnedKey,
            maxAge: VerifiedGraphPeerRelay.SnapshotFreshnessWindow);
        Assert.NotNull(verified);
        Assert.Equal(4, verified.Graph.Threats.Count);
        Assert.Equal("dep:npm:@zalastax/nolb-react-rk@*", verified.Graph.Threats[2].Identifier);
    }
}
