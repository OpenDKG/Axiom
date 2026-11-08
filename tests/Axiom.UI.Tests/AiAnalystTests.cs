// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Axiom.Contracts.Ai;
using Axiom.Contracts.Monitoring;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class AiAnalystTests
{
    [Fact]
    public void Evidence_redacts_local_paths_and_bounds_connections()
    {
        var connections = new[]
        {
            NewConnection(@"C:\Users\alice\bin\app.exe", "203.0.113.10:443"),
            NewConnection(@"C:\Users\alice\bin\other.exe", "203.0.113.11:443"),
        };

        var evidence = AiEvidenceBuilder.Build(connections, "test", [], 1, redactPaths: true);

        Assert.Single(evidence.Connections);
        Assert.Equal("app.exe", evidence.Connections[0].Path);
        Assert.Equal("test", evidence.SourceName);
    }

    [Fact]
    public async Task Provider_response_is_normalized_and_safe_like_status_is_not_accepted()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(new
                {
                    choices = new[]
                    {
                        new
                        {
                            message = new
                            {
                                content = "{\"status\":\"SAFE\",\"severity\":\"low\",\"confidence\":\"high\",\"summary\":\"ok\"}",
                            },
                        },
                    },
                }),
                Encoding.UTF8,
                "application/json"),
        });
        using var http = new HttpClient(handler);
        using var client = new AiAnalystClient(http);
        var evidence = AiEvidenceBuilder.Build([NewConnection("app.exe", "203.0.113.10:443")], "test", [], 5, true);

        var finding = await client.AnalyzeAsync(NewSettings(), "secret", evidence, CancellationToken.None);

        Assert.Equal("UNKNOWN", finding.Status);
        Assert.Equal("low", finding.Severity);
        Assert.Equal("test-model", finding.Model);
        Assert.Null(finding.Error);
    }

    [Fact]
    public async Task Optional_verifier_uses_a_separate_request_and_records_its_status()
    {
        var calls = 0;
        var handler = new StubHandler(_ =>
        {
            calls++;
            var content = calls == 1
                ? "{\"status\":\"SUSPICIOUS\",\"severity\":\"low\",\"confidence\":\"low\",\"summary\":\"lead\"}"
                : "{\"status\":\"INSUFFICIENT_DATA\",\"severity\":\"unknown\",\"confidence\":\"none\",\"summary\":\"not enough evidence\"}";
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new
                    {
                        choices = new[] { new { message = new { content } } },
                    }),
                    Encoding.UTF8,
                    "application/json"),
            };
        });
        using var http = new HttpClient(handler);
        using var client = new AiAnalystClient(http);
        var settings = NewSettings() with { VerifierModel = "verifier-model" };
        var evidence = AiEvidenceBuilder.Build([NewConnection("app.exe", "203.0.113.10:443")], "test", [], 5, true);

        var finding = await client.AnalyzeAsync(settings, "secret", evidence, CancellationToken.None);

        Assert.Equal(2, calls);
        Assert.Equal("SUSPICIOUS", finding.Status);
        Assert.Equal("verifier-model", finding.VerifierModel);
        Assert.Equal("INSUFFICIENT_DATA", finding.VerifierStatus);
        Assert.Equal("not enough evidence", finding.VerifierSummary);
    }

    [Fact]
    public async Task Invalid_provider_json_returns_insufficient_data()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """{"choices":[{"message":{"content":"not json"}}]}""",
                Encoding.UTF8,
                "application/json"),
        });
        using var http = new HttpClient(handler);
        using var client = new AiAnalystClient(http);
        var evidence = AiEvidenceBuilder.Build([NewConnection("app.exe", "203.0.113.10:443")], "test", [], 5, true);

        var finding = await client.AnalyzeAsync(NewSettings(), "secret", evidence, CancellationToken.None);

        Assert.Equal("INSUFFICIENT_DATA", finding.Status);
        Assert.NotNull(finding.Error);
    }

    [Fact]
    public async Task Anthropic_requests_use_the_messages_api_and_x_api_key()
    {
        var handler = new CaptureHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """{"content":[{"type":"text","text":"{\"status\":\"SUSPICIOUS\",\"severity\":\"medium\",\"confidence\":\"low\",\"summary\":\"test\"}"}]}""",
                Encoding.UTF8,
                "application/json"),
        });
        using var http = new HttpClient(handler);
        using var client = new AiAnalystClient(http);
        var settings = NewSettings() with
        {
            Provider = AiProviderKind.Anthropic,
            Endpoint = "https://api.anthropic.com/v1/messages",
            Model = "claude-test",
        };
        var evidence = AiEvidenceBuilder.Build([NewConnection("app.exe", "203.0.113.10:443")], "test", [], 5, true);

        var finding = await client.AnalyzeAsync(settings, "secret", evidence, CancellationToken.None);

        Assert.Equal("secret", handler.ApiKey);
        Assert.Null(handler.Authorization);
        Assert.NotNull(handler.Body);
        using var request = JsonDocument.Parse(handler.Body!);
        Assert.True(request.RootElement.TryGetProperty("system", out _));
        var messages = request.RootElement.GetProperty("messages");
        Assert.Equal("user", messages[0].GetProperty("role").GetString());
        Assert.Equal("SUSPICIOUS", finding.Status);
        Assert.Equal("claude-test", finding.Model);
    }

    [Fact]
    public async Task Cloud_http_endpoint_is_rejected()
    {
        using var client = new AiAnalystClient();
        var settings = NewSettings() with { Endpoint = "http://example.test/v1/chat/completions" };
        var evidence = AiEvidenceBuilder.Build([NewConnection("app.exe", "203.0.113.10:443")], "test", [], 5, true);

        var finding = await client.AnalyzeAsync(settings, "secret", evidence, CancellationToken.None);

        Assert.Equal("INSUFFICIENT_DATA", finding.Status);
        Assert.Contains("HTTPS", finding.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Provider_json_is_extracted_from_prose_and_a_fenced_block()
    {
        const string content =
            "Here is the result:\n```json\n" +
            "{\"status\":\"SUSPICIOUS\",\"severity\":\"medium\",\"confidence\":\"low\",\"summary\":\"test\"}\n" +
            "```\nDone.";
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(new
                {
                    choices = new[] { new { message = new { content } } },
                }),
                Encoding.UTF8,
                "application/json"),
        });
        using var http = new HttpClient(handler);
        using var client = new AiAnalystClient(http);
        var evidence = AiEvidenceBuilder.Build([NewConnection("app.exe", "203.0.113.10:443")], "test", [], 5, true);

        var finding = await client.AnalyzeAsync(NewSettings(), "secret", evidence, CancellationToken.None);

        Assert.Equal("SUSPICIOUS", finding.Status);
        Assert.Equal("medium", finding.Severity);
        Assert.Null(finding.Error);
    }

    [Fact]
    public void Evidence_adds_service_annotations_duration_and_host_context()
    {
        var evidence = AiEvidenceBuilder.Build(
            [NewConnection("app.exe", "203.0.113.10:443")],
            "test",
            ["source limitation"],
            5,
            redactPaths: true);

        var connection = Assert.Single(evidence.Connections);
        Assert.Equal("https", connection.RemotePortService);
        Assert.True(connection.ObservedDurationSeconds >= 0);
        Assert.NotNull(evidence.Host);
        Assert.Contains(evidence.Limitations, item => item.Contains("source limitation", StringComparison.Ordinal));
        Assert.Contains(evidence.Limitations, item => item.Contains("ETW", StringComparison.Ordinal));
    }

    [Fact]
    public void Settings_store_protects_the_api_key_with_dpapi()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-ai-settings-{Guid.NewGuid():N}.json");
        try
        {
            var store = new AiAnalystSettingsStore(path);
            var settings = NewSettings();

            Assert.True(store.Save(settings, "local-secret"));
            var (loaded, key) = store.Load();

            Assert.Equal("test-model", loaded.Model);
            Assert.Equal("local-secret", key);
            Assert.DoesNotContain("local-secret", File.ReadAllText(path), StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Finding_store_round_trips_without_prompt_content()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-ai-{Guid.NewGuid():N}.json");
        try
        {
            var store = new AiFindingStore(path);
            var finding = new AiFinding
            {
                Status = "UNKNOWN",
                Severity = "unknown",
                Confidence = "none",
                Summary = "test",
                Model = "test-model",
            };

            Assert.True(store.Save(finding));
            var loaded = Assert.Single(store.LoadRecent());
            Assert.Equal("test", loaded.Summary);
            Assert.DoesNotContain("prompt", File.ReadAllText(path), StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static AiAnalystSettings NewSettings() => new()
    {
        Enabled = true,
        Endpoint = "https://example.test/v1/chat/completions",
        Model = "test-model",
        RedactPaths = true,
        MaxConnections = 5,
        MaxTokens = 512,
    };

    private static LiveConnection NewConnection(string path, string remote) => new()
    {
        AppDisplayName = Path.GetFileName(path),
        AppPath = path,
        ProcessId = 42,
        Protocol = TransportProtocol.Tcp,
        LocalEndpoint = "192.0.2.10:50000",
        RemoteEndpoint = remote,
        State = "Established",
        Direction = ConnectionDirection.Outbound,
        InterfaceName = string.Empty,
        FirstObservedUtc = DateTimeOffset.UtcNow,
        Quality = DataQuality.Observed,
    };

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }

    private sealed class CaptureHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public string? Body { get; private set; }

        public string? ApiKey { get; private set; }

        public string? Authorization { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Body = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            ApiKey = request.Headers.TryGetValues("x-api-key", out var keys) ? keys.FirstOrDefault() : null;
            Authorization = request.Headers.Authorization?.ToString();
            return respond(request);
        }
    }
}
