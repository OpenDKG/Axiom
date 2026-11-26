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

    private static readonly string[] SampleObservations = ["Outbound beacon"];
    private static readonly string[] SampleEvidenceRefs = ["conn-1"];
    private static readonly string[] SampleRecommendedActions = ["Inspect manually"];

    [Fact]
    public async Task Client_parses_and_bounds_structured_indicators()
    {
        var indicators = Enumerable.Range(0, 14)
            .Select(i => new { type = "DOMAIN", value = $"c2-{i}.example.test", role = "malicious" })
            .ToArray();
        var structuredJson = JsonSerializer.Serialize(new
        {
            status = "SUSPICIOUS",
            severity = "high",
            confidence = "medium",
            summary = "Bounded indicator parity test.",
            observations = SampleObservations,
            evidenceReferences = SampleEvidenceRefs,
            alternativeExplanations = Array.Empty<string>(),
            missingEvidence = Array.Empty<string>(),
            recommendedActions = SampleRecommendedActions,
            indicators,
        });
        var chatResponse = JsonSerializer.Serialize(new
        {
            choices = new[] { new { message = new { content = structuredJson } } },
        });

        using var http = new HttpClient(new StubHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(chatResponse, System.Text.Encoding.UTF8, "application/json"),
            }));
        using var client = new AiAnalystClient(http);
        var finding = await client.AnalyzeAsync(
            NewSettings(),
            "test-key",
            new AiEvidencePackage("2", DateTimeOffset.UtcNow, "test", "redacted", [], []),
            CancellationToken.None);

        Assert.Null(finding.Error);
        Assert.Equal(10, finding.Indicators.Count);
        Assert.All(finding.Indicators, ind =>
        {
            Assert.Equal("domain", ind.Type);
            Assert.Equal("malicious", ind.Role);
        });
    }

    [Fact]
    public async Task GoogleGemini_uses_bearer_auth_and_parses_response()
    {
        var handler = new CaptureHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """{"choices":[{"message":{"content":"{\"status\":\"LOW_OBSERVED_RISK\",\"severity\":\"low\",\"confidence\":\"medium\",\"summary\":\"gemini ok\"}"}}]}""",
                Encoding.UTF8,
                "application/json"),
        });
        using var http = new HttpClient(handler);
        using var client = new AiAnalystClient(http);
        var settings = NewSettings() with
        {
            Provider = AiProviderKind.GoogleGemini,
            Endpoint = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            Model = "gemini-2.5-flash",
        };
        var evidence = AiEvidenceBuilder.Build([NewConnection("app.exe", "203.0.113.10:443")], "test", [], 5, true);

        var finding = await client.AnalyzeAsync(settings, "AIzaSyTestKey", evidence, CancellationToken.None);

        Assert.Null(finding.Error);
        Assert.Equal("LOW_OBSERVED_RISK", finding.Status);
        Assert.Equal("Bearer AIzaSyTestKey", handler.Authorization);
        Assert.Equal("gemini-2.5-flash", finding.Model);
    }

    [Fact]
    public async Task OpenRouter_sends_attribution_headers_and_parses_response()
    {
        var handler = new CaptureHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """{"choices":[{"message":{"content":"{\"status\":\"SUSPICIOUS\",\"severity\":\"medium\",\"confidence\":\"low\",\"summary\":\"openrouter ok\"}"}}]}""",
                Encoding.UTF8,
                "application/json"),
        });
        using var http = new HttpClient(handler);
        using var client = new AiAnalystClient(http);
        var settings = NewSettings() with
        {
            Provider = AiProviderKind.OpenRouter,
            Endpoint = "https://openrouter.ai/api/v1/chat/completions",
            Model = "google/gemini-2.5-flash",
        };
        var evidence = AiEvidenceBuilder.Build([NewConnection("app.exe", "203.0.113.10:443")], "test", [], 5, true);

        var finding = await client.AnalyzeAsync(settings, "sk-or-v1-test", evidence, CancellationToken.None);

        Assert.Null(finding.Error);
        Assert.Equal("SUSPICIOUS", finding.Status);
        Assert.Equal("Bearer sk-or-v1-test", handler.Authorization);
        Assert.Equal("https://github.com/OpenDKG/Axiom", handler.HttpReferer);
        Assert.Equal("Axiom Firewall", handler.XTitle);
    }

    [Theory]
    [InlineData(AiProviderKind.Anthropic, "https://api.anthropic.com/v1/messages", "claude-sonnet-4-5", "sk-ant-oat01-blocked")]
    [InlineData(AiProviderKind.GoogleGemini, "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "gemini-2.5-flash", "ya29.blocked")]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://cloudcode-pa.googleapis.com/v1internal", "gemini-2.5-pro", "AIzaSyTest")]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://claude.ai/api/organizations", "claude-sonnet-4-5", "secret")]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://chatgpt.com/backend-api/conversation", "gpt-5", "secret")]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://api.githubcopilot.com/chat/completions", "gpt-4o", "secret")]
    public async Task Blocked_oauth_tokens_and_endpoints_are_rejected_before_http_send(
        AiProviderKind provider,
        string endpoint,
        string model,
        string apiKey)
    {
        var handler = new CaptureHandler(_ => throw new InvalidOperationException("HTTP should not be invoked."));
        using var http = new HttpClient(handler);
        using var client = new AiAnalystClient(http);
        var settings = NewSettings() with
        {
            Provider = provider,
            Endpoint = endpoint,
            Model = model,
        };
        var evidence = AiEvidenceBuilder.Build([NewConnection("app.exe", "203.0.113.10:443")], "test", [], 5, true);

        var finding = await client.AnalyzeAsync(settings, apiKey, evidence, CancellationToken.None);

        Assert.Equal(0, handler.CallCount);
        Assert.Equal("INSUFFICIENT_DATA", finding.Status);
        Assert.False(string.IsNullOrWhiteSpace(finding.Error));
    }

    [Theory]
    [InlineData("anthropic/claude-sonnet-4-5", "")]
    [InlineData("antigravity/gemini-2.5-pro", "")]
    [InlineData("opencode/free", "")]
    [InlineData("opencode-go/deepseek-v4.1-flash", "github-copilot/gpt-4o")]
    public async Task Blocked_opencode_models_are_rejected_before_spawning_opencode(
        string model,
        string verifierModel)
    {
        using var client = new AiAnalystClient();
        var settings = NewSettings() with
        {
            Provider = AiProviderKind.OpenChamberLocal,
            Endpoint = "opencode://local",
            Model = model,
            VerifierModel = verifierModel,
        };
        var evidence = AiEvidenceBuilder.Build([NewConnection("app.exe", "203.0.113.10:443")], "test", [], 5, true);

        var finding = await client.AnalyzeAsync(settings, string.Empty, evidence, CancellationToken.None);

        Assert.Equal("INSUFFICIENT_DATA", finding.Status);
        Assert.Contains("ToS", finding.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Default_client_does_not_follow_provider_redirects()
    {
        using var target = new LoopbackHttpServer(_ => "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        using var redirector = new LoopbackHttpServer(_ =>
            $"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{target.Port}/v1/chat/completions\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        using var client = new AiAnalystClient();
        var settings = new AiAnalystSettings
        {
            Enabled = true,
            Provider = AiProviderKind.LocalOpenAiCompatible,
            Endpoint = $"http://127.0.0.1:{redirector.Port}/v1/chat/completions",
            Model = "llama3.1",
        };

        var finding = await client.AnalyzeAsync(settings, "local-key", AiEvidenceBuilder.Build([NewConnection("app.exe", "203.0.113.10:443")], "test", [], 5, true), CancellationToken.None);

        Assert.Equal(1, redirector.RequestCount);
        Assert.Equal(0, target.RequestCount);
        Assert.Contains("redirect", finding.Error, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class LoopbackHttpServer : IDisposable
    {
        private readonly System.Net.Sockets.TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly Func<string, string> _respond;
        private int _requestCount;

        public LoopbackHttpServer(Func<string, string> respond)
        {
            _respond = respond;
            _listener.Start();
            _ = Task.Run(ServeAsync);
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public int RequestCount => Volatile.Read(ref _requestCount);

        public void Dispose()
        {
            _stop.Cancel();
            _listener.Stop();
            _stop.Dispose();
        }

        private async Task ServeAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                System.Net.Sockets.TcpClient connection;
                try
                {
                    connection = await _listener.AcceptTcpClientAsync(_stop.Token);
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or System.Net.Sockets.SocketException)
                {
                    return;
                }

                using (connection)
                {
                    var stream = connection.GetStream();
                    var request = await ReadRequestAsync(stream);
                    Interlocked.Increment(ref _requestCount);
                    var response = Encoding.ASCII.GetBytes(_respond(request));
                    await stream.WriteAsync(response);
                    await stream.FlushAsync();
                }
            }
        }

        private static async Task<string> ReadRequestAsync(Stream stream)
        {
            var buffer = new byte[16384];
            var received = new MemoryStream();
            while (true)
            {
                var read = await stream.ReadAsync(buffer);
                if (read == 0)
                {
                    break;
                }

                received.Write(buffer, 0, read);
                var text = Encoding.ASCII.GetString(received.ToArray());
                var headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (headerEnd < 0)
                {
                    continue;
                }

                var lengthLine = text[..headerEnd].Split("\r\n")
                    .FirstOrDefault(line => line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
                var length = lengthLine is null ? 0 : int.Parse(lengthLine["Content-Length:".Length..].Trim(), System.Globalization.CultureInfo.InvariantCulture);
                if (received.Length >= headerEnd + 4 + length)
                {
                    return text;
                }
            }

            return Encoding.ASCII.GetString(received.ToArray());
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
        public int CallCount { get; private set; }

        public string? Body { get; private set; }

        public string? ApiKey { get; private set; }

        public string? Authorization { get; private set; }

        public string? HttpReferer { get; private set; }

        public string? XTitle { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            CallCount++;
            Body = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            ApiKey = request.Headers.TryGetValues("x-api-key", out var keys) ? keys.FirstOrDefault() : null;
            Authorization = request.Headers.Authorization?.ToString();
            HttpReferer = request.Headers.TryGetValues("HTTP-Referer", out var referers)
                ? referers.FirstOrDefault()
                : null;
            XTitle = request.Headers.TryGetValues("X-Title", out var titles)
                ? titles.FirstOrDefault()
                : null;
            return respond(request);
        }
    }
}
