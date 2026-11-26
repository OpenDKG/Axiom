// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ai;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class AiProviderCompliancePolicyTests
{
    [Fact]
    public void GetPresets_covers_all_providers_with_local_and_official_apis_ahead_of_opencode()
    {
        var presets = AiProviderCompliancePolicy.GetPresets();
        var kinds = presets.Select(preset => preset.Kind).ToArray();

        Assert.Equal(Enum.GetValues<AiProviderKind>().Length, presets.Count);
        Assert.Equal(presets.Count, kinds.Distinct().Count());
        foreach (var kind in Enum.GetValues<AiProviderKind>())
        {
            Assert.Contains(kind, kinds);
            Assert.True(AiProviderCompliancePolicy.TryGetPreset(kind, out var preset));
            Assert.NotNull(preset);
            Assert.False(string.IsNullOrWhiteSpace(preset.Label));
            Assert.False(string.IsNullOrWhiteSpace(preset.ComplianceNote));
            Assert.Equal(preset.ComplianceNote, AiProviderCompliancePolicy.GetComplianceNote(kind));
        }

        var openCodeIndex = Array.IndexOf(kinds, AiProviderKind.OpenChamberLocal);
        Assert.Equal(presets.Count - 1, openCodeIndex);
        Assert.Equal(AiProviderKind.LocalOpenAiCompatible, kinds[0]);
        Assert.True(Array.IndexOf(kinds, AiProviderKind.GoogleGemini) < openCodeIndex);
        Assert.True(Array.IndexOf(kinds, AiProviderKind.OpenRouter) < openCodeIndex);
        Assert.True(Array.IndexOf(kinds, AiProviderKind.Anthropic) < openCodeIndex);
        Assert.True(Array.IndexOf(kinds, AiProviderKind.OpenAi) < openCodeIndex);
    }

    [Fact]
    public void TryGetPreset_returns_false_for_unknown_provider_and_GetComplianceNote_returns_guidance()
    {
        Assert.False(AiProviderCompliancePolicy.TryGetPreset((AiProviderKind)999, out var preset));
        Assert.Null(preset);
        Assert.False(string.IsNullOrWhiteSpace(
            AiProviderCompliancePolicy.GetComplianceNote((AiProviderKind)999)));
    }

    [Fact]
    public void ValidateRequest_throws_on_null_settings()
    {
        Assert.Throws<ArgumentNullException>(() =>
            AiProviderCompliancePolicy.ValidateRequest(null!, "secret", out _));
    }

    [Theory]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://cloudcode-pa.googleapis.com/v1internal:generateContent")]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://daily-cloudcode-pa.cloudcode-pa.googleapis.com/v1internal")]
    [InlineData(AiProviderKind.GoogleGemini, "https://cloudcode-pa.googleapis.com/v1beta/openai/chat/completions")]
    [InlineData(AiProviderKind.Anthropic, "https://claude.ai/api/organizations")]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://api.claude.ai/v1/messages")]
    [InlineData(AiProviderKind.OpenAi, "https://chatgpt.com/backend-api/conversation")]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://sub.chatgpt.com/v1/chat/completions")]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://chat.openai.com/backend-api/conversation")]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://api.githubcopilot.com/chat/completions")]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://copilot-proxy.githubusercontent.com/v1/engines")]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://CLAUDE.AI/v1/messages")]
    public void ValidateRequest_blocks_consumer_and_private_endpoints(AiProviderKind provider, string endpoint)
    {
        var settings = new AiAnalystSettings
        {
            Enabled = true,
            Provider = provider,
            Endpoint = endpoint,
            Model = "test-model",
        };

        var allowed = AiProviderCompliancePolicy.ValidateRequest(settings, "api-key", out var error);

        Assert.False(allowed);
        Assert.Contains("blocked", error, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(AiProviderKind.Anthropic, "https://api.anthropic.com/v1/messages", "sk-ant-oat01-token")]
    [InlineData(AiProviderKind.Anthropic, "https://api.anthropic.com/v1/messages", "  SK-ANT-OAT02-TOKEN  ")]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://api.anthropic.com/v1/messages", "sk-ant-oat01-token")]
    public void ValidateRequest_blocks_anthropic_consumer_oauth_tokens(
        AiProviderKind provider,
        string endpoint,
        string apiKey)
    {
        var settings = new AiAnalystSettings
        {
            Enabled = true,
            Provider = provider,
            Endpoint = endpoint,
            Model = "claude-sonnet-4-5",
        };

        var allowed = AiProviderCompliancePolicy.ValidateRequest(settings, apiKey, out var error);

        Assert.False(allowed);
        Assert.Contains("sk-ant-api", error, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("MCP", error, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(AiProviderKind.GoogleGemini, "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "ya29.a0AfH6SMtoken")]
    [InlineData(AiProviderKind.GoogleGemini, "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "  YA29.token  ")]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "ya29.token")]
    public void ValidateRequest_blocks_google_consumer_oauth_tokens(
        AiProviderKind provider,
        string endpoint,
        string apiKey)
    {
        var settings = new AiAnalystSettings
        {
            Enabled = true,
            Provider = provider,
            Endpoint = endpoint,
            Model = "gemini-2.5-flash",
        };

        var allowed = AiProviderCompliancePolicy.ValidateRequest(settings, apiKey, out var error);

        Assert.False(allowed);
        Assert.Contains("AIza", error, StringComparison.Ordinal);
        Assert.Contains("MCP", error, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(AiProviderKind.LocalOpenAiCompatible, "http://127.0.0.1:11434/v1/chat/completions", "llama3.1", "")]
    [InlineData(AiProviderKind.OpenAi, "https://api.openai.com/v1/chat/completions", "gpt-5.1", "sk-proj-test")]
    [InlineData(AiProviderKind.Anthropic, "https://api.anthropic.com/v1/messages", "claude-sonnet-4-5", "sk-ant-api03-test")]
    [InlineData(AiProviderKind.GoogleGemini, "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "gemini-2.5-flash", "AIzaSyTestKey")]
    [InlineData(AiProviderKind.OpenRouter, "https://openrouter.ai/api/v1/chat/completions", "google/gemini-2.5-flash", "sk-or-v1-test")]
    [InlineData(AiProviderKind.DeepSeek, "https://api.deepseek.com/chat/completions", "deepseek-chat", "sk-ds-test")]
    [InlineData(AiProviderKind.Zai, "https://api.z.ai/api/paas/v4/chat/completions", "glm-5.3", "zai-test")]
    [InlineData(AiProviderKind.OpenCodeZen, "https://opencode.ai/zen/v1/chat/completions", "deepseek-v4.1-flash", "zen-test")]
    [InlineData(AiProviderKind.OpenAiCompatible, "https://example.test/v1/chat/completions", "test-model", "secret")]
    public void ValidateRequest_allows_compliant_http_providers_and_official_keys(
        AiProviderKind provider,
        string endpoint,
        string model,
        string apiKey)
    {
        var settings = new AiAnalystSettings
        {
            Enabled = true,
            Provider = provider,
            Endpoint = endpoint,
            Model = model,
        };

        var allowed = AiProviderCompliancePolicy.ValidateRequest(settings, apiKey, out var error);

        Assert.True(allowed, error);
        Assert.Equal(string.Empty, error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("anthropic/claude-sonnet-4-5")]
    [InlineData("  Anthropic/claude-3-7-sonnet  ")]
    [InlineData("claude/claude-sonnet-4-5")]
    [InlineData("claude-code/claude-sonnet-4-5")]
    [InlineData("antigravity/gemini-2.5-pro")]
    [InlineData("google/gemini-2.5-pro")]
    [InlineData("google-gemini-cli/gemini-2.5-pro")]
    [InlineData("gemini/gemini-2.5-flash")]
    [InlineData("gemini-cli/gemini-2.5-pro")]
    [InlineData("vertex-antigravity/claude-sonnet-4-5")]
    [InlineData("github-copilot/gpt-4o")]
    [InlineData("copilot/gpt-4o")]
    [InlineData("chatgpt/gpt-5")]
    [InlineData("codex/gpt-5-codex")]
    [InlineData("openai-codex/gpt-5-codex")]
    [InlineData("cursor/default")]
    [InlineData("windsurf/default")]
    [InlineData("claude-sonnet-4-5")]
    [InlineData("CLAUDE-3-5-sonnet")]
    [InlineData("antigravity")]
    [InlineData("antigravity-pro")]
    [InlineData("gemini-cli")]
    [InlineData("gemini-cli-2.5-pro")]
    [InlineData("openrouter/deepseek/deepseek-chat:free")]
    [InlineData("deepseek/deepseek-chat:FREE")]
    [InlineData("free")]
    [InlineData("opencode/free")]
    [InlineData("opencode/free-tier")]
    public void ValidateOpenCodeModel_blocks_restricted_providers_bare_models_and_free_routes(string? model)
    {
        var allowed = AiProviderCompliancePolicy.ValidateOpenCodeModel(model, out var error);

        Assert.False(allowed);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Theory]
    [InlineData("opencode-go/deepseek-v4.1-flash")]
    [InlineData("ollama/llama3.1")]
    [InlineData("lmstudio/qwen2.5-coder")]
    [InlineData("deepseek/deepseek-chat")]
    [InlineData("openrouter/anthropic/claude-sonnet-4-5")]
    [InlineData("example/model")]
    public void ValidateOpenCodeModel_allows_authorized_opencode_providers(string model)
    {
        var allowed = AiProviderCompliancePolicy.ValidateOpenCodeModel(model, out var error);

        Assert.True(allowed, error);
        Assert.Equal(string.Empty, error);

        var settings = new AiAnalystSettings
        {
            Enabled = true,
            Provider = AiProviderKind.OpenChamberLocal,
            Endpoint = "opencode://local",
            Model = model,
        };
        Assert.True(AiProviderCompliancePolicy.ValidateRequest(settings, null, out var requestError), requestError);
    }

    [Theory]
    [InlineData("anthropic/claude-sonnet-4-5")]
    [InlineData("openrouter/meta-llama/llama-3.3-70b-instruct:free")]
    public void ValidateRequest_blocks_restricted_opencode_verifier_model(string verifierModel)
    {
        var settings = new AiAnalystSettings
        {
            Enabled = true,
            Provider = AiProviderKind.OpenChamberLocal,
            Endpoint = "opencode://local",
            Model = "opencode-go/deepseek-v4.1-flash",
            VerifierModel = verifierModel,
        };

        var allowed = AiProviderCompliancePolicy.ValidateRequest(settings, null, out var error);

        Assert.False(allowed);
        Assert.Contains("ToS", error, StringComparison.OrdinalIgnoreCase);
    }
}
