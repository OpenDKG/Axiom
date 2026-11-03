// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http;
using System.Text;
using Netpetra.Contracts.Reputation;
using Xunit;

namespace Netpetra.Contracts.Tests;

public sealed class VirusTotalClientTests
{
    private const string Hash = "44D88612FEA8A8F36DE82E1278ABB02F2C4B4B0F9B0B0B0B0B0B0B0B0B0B0B0B";

    [Fact]
    public async Task Hash_lookup_sends_only_the_hash_and_parses_stats()
    {
        HttpRequestMessage? captured = null;
        var handler = new StubHandler(request =>
        {
            captured = request;
            return Json(HttpStatusCode.OK, """
                {
                  "data": {
                    "attributes": {
                      "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "undetected": 60,
                        "harmless": 2
                      },
                      "meaningful_name": "example.exe",
                      "type_description": "Win32 EXE",
                      "last_analysis_date": 1700000000
                    }
                  }
                }
                """);
        });
        using var http = new HttpClient(handler);
        using var client = new VirusTotalClient(http);

        var report = await client.LookupHashAsync(Hash, "test-key", CancellationToken.None);

        Assert.True(report.Found);
        Assert.Equal(3, report.Malicious);
        Assert.Equal(1, report.Suspicious);
        Assert.Equal("example.exe", report.Name);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1700000000), report.LastAnalysisUtc);
        Assert.NotNull(captured);
        Assert.Equal($"https://www.virustotal.com/api/v3/files/{Hash}", captured!.RequestUri!.ToString());
        Assert.Equal("test-key", captured.Headers.GetValues("x-apikey").Single());
    }

    [Fact]
    public async Task NotFound_is_reported_as_not_found()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        using var http = new HttpClient(handler);
        using var client = new VirusTotalClient(http);

        var report = await client.LookupHashAsync(Hash, "test-key", CancellationToken.None);

        Assert.False(report.Found);
        Assert.Equal("Hash not found by VirusTotal", report.Summary);
    }

    [Fact]
    public async Task Invalid_hash_is_rejected_before_a_request()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, "{}"));
        using var http = new HttpClient(handler);
        using var client = new VirusTotalClient(http);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.LookupHashAsync("not-a-hash", "test-key", CancellationToken.None));
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string json) => new(status)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
