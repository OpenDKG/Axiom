// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Axiom.Contracts.Blackbox;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class ThreatSharingConsentTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "axiom-consent-" + Guid.NewGuid().ToString("N"));

    public ThreatSharingConsentTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public void Legacy_complete_consent_does_not_authorize_manual_reporting()
    {
        var profile = Path.Combine(_directory, "install-profile.json");
        File.WriteAllText(profile, """{"profile":"complete","threatSharingConsent":true}""");

        Assert.False(ThreatSharingConsent.HasConsent(profile));
    }

    [Fact]
    public void Missing_or_partial_consent_is_false()
    {
        Assert.False(ThreatSharingConsent.HasConsent(Path.Combine(_directory, "missing.json")));

        var profile = Path.Combine(_directory, "install-profile.json");
        File.WriteAllText(profile, """{"profile":"partial"}""");
        Assert.False(ThreatSharingConsent.HasConsent(profile));
    }

    [Fact]
    public void Manual_permission_can_be_granted_and_withdrawn()
    {
        var path = Path.Combine(_directory, "manual-threat-sharing");
        Assert.False(ThreatSharingConsent.HasConsent(path));
        Assert.True(ThreatSharingConsent.TrySetPermission(true, path));
        Assert.True(ThreatSharingConsent.HasConsent(path));
        Assert.True(ThreatSharingConsent.TrySetPermission(false, path));
        Assert.False(ThreatSharingConsent.HasConsent(path));
    }

    [Fact]
    public async Task Automatic_sharing_default_applies_once_and_preserves_pending_when_offline()
    {
        var marker = Path.Combine(_directory, "auto-sharing-default");
        Assert.False(BlackboxAutomaticSharingProvisioner.IsPending(marker));
        Assert.True(BlackboxAutomaticSharingProvisioner.TryMarkPending(marker));
        Assert.True(BlackboxAutomaticSharingProvisioner.IsPending(marker));

        using var offlineHttp = new HttpClient(new StubHandler(online: false, onReport: _ => { }))
        {
            BaseAddress = new Uri("http://127.0.0.1:9700/"),
        };
        using var offlineClient = new BlackboxDashboardClient(offlineHttp);
        Assert.False(await BlackboxAutomaticSharingProvisioner.TryApplyToDashboardAsync(
            offlineClient, CancellationToken.None, marker));
        Assert.True(BlackboxAutomaticSharingProvisioner.IsPending(marker));

        bool? saved = null;
        using var onlineHttp = new HttpClient(new StubHandler(online: true, onReport: value => saved = value))
        {
            BaseAddress = new Uri("http://127.0.0.1:9700/"),
        };
        using var onlineClient = new BlackboxDashboardClient(onlineHttp);
        Assert.True(await BlackboxAutomaticSharingProvisioner.TryApplyToDashboardAsync(
            onlineClient, CancellationToken.None, marker));
        Assert.Equal(true, saved);
        Assert.False(BlackboxAutomaticSharingProvisioner.IsPending(marker));
        Assert.True(BlackboxAutomaticSharingProvisioner.IsApplied(marker));
    }

    private sealed class StubHandler(bool online, Action<bool> onReport) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (!online)
            {
                throw new HttpRequestException("dashboard offline");
            }

            var path = request.RequestUri?.AbsolutePath ?? string.Empty;
            if (path == "/api/session")
            {
                return Json("""{"token":"tok"}""");
            }

            if (request.Method == HttpMethod.Post && path == "/api/settings")
            {
                var body = request.Content is null
                    ? string.Empty
                    : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                if (JsonNode.Parse(body) is JsonObject obj &&
                    obj["report"] is JsonValue val &&
                    val.TryGetValue<bool>(out var enabled))
                {
                    onReport(enabled);
                }

                return Json("""{"ok":true,"settings":{"report":true}}""");
            }

            return Json("""{"report":true}""");
        }

        private static HttpResponseMessage Json(string body) =>
            new(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
    }
}
