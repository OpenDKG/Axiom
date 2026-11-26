// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Text;
using System.Text.Json;
using Axiom.Contracts.Ai;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class AiAnalystSafetyTests
{
    [Fact]
    public void OpenCode_request_uses_independent_server_and_deny_all_tool_configuration()
    {
        var workingDirectory = Path.GetTempPath();
        var start = OpenCodeAnalystLaunch.CreateRequest("opencode", workingDirectory, "example/model");

        Assert.Equal(["run", "--standalone", "--format", "json", "--agent", "axiom-analyst", "--model", "example/model"],
            start.ArgumentList);
        Assert.False(start.UseShellExecute);
        Assert.True(start.RedirectStandardInput);
        Assert.Equal(Path.Combine(workingDirectory, "config"), start.Environment["XDG_CONFIG_HOME"]);
        Assert.Equal(":memory:", start.Environment["OPENCODE_DB"]);
        Assert.Equal("true", start.Environment["OPENCODE_DISABLE_PROJECT_CONFIG"]);
        Assert.False(start.Environment.ContainsKey("OPENCODE_CONFIG_DIR"));
        Assert.False(start.Environment.ContainsKey("OPENCODE_CONFIG"));
        Assert.False(start.Environment.ContainsKey("OPENCODE_CLI_CONFIG_CONTENT"));
        Assert.False(start.Environment.ContainsKey("CLAUDE_CODE_OAUTH_TOKEN"));
        Assert.False(start.Environment.ContainsKey("ANTHROPIC_AUTH_TOKEN"));
        Assert.False(start.Environment.ContainsKey("GOOGLE_CLOUD_ACCESS_TOKEN"));
        Assert.False(start.Environment.ContainsKey("GEMINI_CLI_OAUTH_TOKEN"));

        using var config = JsonDocument.Parse(start.Environment["OPENCODE_CONFIG_CONTENT"]!);
        var agent = config.RootElement.GetProperty("agents").GetProperty("axiom-analyst");
        var permission = Assert.Single(agent.GetProperty("permissions").EnumerateArray());
        Assert.Equal("*", permission.GetProperty("action").GetString());
        Assert.Equal("*", permission.GetProperty("resource").GetString());
        Assert.Equal("deny", permission.GetProperty("effect").GetString());
        var policies = config.RootElement.GetProperty("policies").EnumerateArray().ToArray();
        Assert.Equal(["tool.use", "mcp.use", "plugin.use", "skill.use"],
            policies.Select(policy => policy.GetProperty("action").GetString()));
        Assert.All(policies, policy =>
        {
            Assert.Equal("*", policy.GetProperty("resource").GetString());
            Assert.Equal("deny", policy.GetProperty("effect").GetString());
        });
    }

    [Theory]
    [InlineData("SUSPICIOUS", "high", null, "High-priority finding")]
    [InlineData("SUPPORTED_ALERT", "critical", null, "High-priority finding")]
    [InlineData("SUSPICIOUS", "medium", null, "Flagged for review")]
    [InlineData("LOW_OBSERVED_RISK", "low", null, "Low observed risk")]
    [InlineData("LOW_OBSERVED_RISK", "critical", null, "Inconclusive")]
    [InlineData("INSUFFICIENT_DATA", "low", null, "Inconclusive")]
    [InlineData("SAFE", "low", null, "Inconclusive")]
    [InlineData("LOW_OBSERVED_RISK", "low", "Provider error", "Analysis failed")]
    public void Badge_classifies_existing_findings_without_changing_the_saved_contract(
        string status, string severity, string? error, string label)
    {
        var finding = new AiFinding { Status = status, Severity = severity, Error = error };
        Assert.Equal(label, finding.Assessment.Label);
        Assert.DoesNotContain("\"Assessment\"", JsonSerializer.Serialize(finding), StringComparison.Ordinal);
    }

    [Fact]
    public async Task GoogleGemini_uses_bearer_auth_and_parses_openai_compatible_choice()
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
        var settings = new AiAnalystSettings
        {
            Enabled = true,
            Provider = AiProviderKind.GoogleGemini,
            Endpoint = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            Model = "gemini-2.5-flash",
        };

        var finding = await client.AnalyzeAsync(settings, "AIzaSyTestKey", NewEvidence(), CancellationToken.None);

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
        var settings = new AiAnalystSettings
        {
            Enabled = true,
            Provider = AiProviderKind.OpenRouter,
            Endpoint = "https://openrouter.ai/api/v1/chat/completions",
            Model = "google/gemini-2.5-flash",
        };

        var finding = await client.AnalyzeAsync(settings, "sk-or-v1-test", NewEvidence(), CancellationToken.None);

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
    public async Task Blocked_oauth_tokens_and_endpoints_fail_before_http_send(
        AiProviderKind provider,
        string endpoint,
        string model,
        string apiKey)
    {
        var handler = new CaptureHandler(_ => throw new InvalidOperationException("HTTP should not be invoked."));
        using var http = new HttpClient(handler);
        using var client = new AiAnalystClient(http);
        var settings = new AiAnalystSettings
        {
            Enabled = true,
            Provider = provider,
            Endpoint = endpoint,
            Model = model,
        };

        var finding = await client.AnalyzeAsync(settings, apiKey, NewEvidence(), CancellationToken.None);

        Assert.Equal(0, handler.CallCount);
        Assert.Equal("INSUFFICIENT_DATA", finding.Status);
        Assert.False(string.IsNullOrWhiteSpace(finding.Error));
    }

    [Theory]
    [InlineData("anthropic/claude-sonnet-4-5", "")]
    [InlineData("antigravity/gemini-2.5-pro", "")]
    [InlineData("opencode/free", "")]
    [InlineData("opencode-go/deepseek-v4.1-flash", "github-copilot/gpt-4o")]
    public async Task Blocked_opencode_models_fail_compliance_before_spawning_opencode(
        string model,
        string verifierModel)
    {
        using var client = new AiAnalystClient();
        var settings = new AiAnalystSettings
        {
            Enabled = true,
            Provider = AiProviderKind.OpenChamberLocal,
            Endpoint = "opencode://local",
            Model = model,
            VerifierModel = verifierModel,
        };

        var finding = await client.AnalyzeAsync(settings, string.Empty, NewEvidence(), CancellationToken.None);

        Assert.Equal("INSUFFICIENT_DATA", finding.Status);
        Assert.Contains("ToS", finding.Error, StringComparison.OrdinalIgnoreCase);
    }

    private static AiEvidencePackage NewEvidence() =>
        new("2", DateTimeOffset.UtcNow, "test", "redacted", [], []);

    private sealed class CaptureHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        public string? Authorization { get; private set; }

        public string? HttpReferer { get; private set; }

        public string? XTitle { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            CallCount++;
            Authorization = request.Headers.Authorization?.ToString();
            HttpReferer = request.Headers.TryGetValues("HTTP-Referer", out var referers)
                ? referers.FirstOrDefault()
                : null;
            XTitle = request.Headers.TryGetValues("X-Title", out var titles)
                ? titles.FirstOrDefault()
                : null;
            return Task.FromResult(respond(request));
        }
    }
}
