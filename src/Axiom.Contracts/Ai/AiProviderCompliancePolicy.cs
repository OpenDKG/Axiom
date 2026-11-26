// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics.CodeAnalysis;

namespace Axiom.Contracts.Ai;

/// <summary>
/// Preset metadata and Terms-of-Service compliance guidance for an AI analyst provider.
/// </summary>
public sealed record AiProviderPreset(
    AiProviderKind Kind,
    string Label,
    string Endpoint,
    string DefaultModel,
    bool RequiresApiKey,
    string ComplianceNote);

/// <summary>
/// Enforces provider Terms-of-Service compliance across AI analyst configuration, endpoints,
/// credentials, and OpenCode local model selection.
/// </summary>
public static class AiProviderCompliancePolicy
{
    private static readonly AiProviderPreset[] Presets =
    [
        new(
            AiProviderKind.LocalOpenAiCompatible,
            "Local model — Ollama / LM Studio (private, no API key)",
            "http://127.0.0.1:11434/v1/chat/completions",
            "llama3.1",
            RequiresApiKey: false,
            "Runs locally on loopback HTTP with Ollama or LM Studio; no cloud account or API key is required."),
        new(
            AiProviderKind.OpenAi,
            "OpenAI (Official Platform API key)",
            "https://api.openai.com/v1/chat/completions",
            "gpt-5.1",
            RequiresApiKey: true,
            "Uses an official OpenAI Platform API key over HTTPS. Consumer ChatGPT web/Codex endpoints are blocked."),
        new(
            AiProviderKind.Anthropic,
            "Anthropic Claude (Official Console API key)",
            "https://api.anthropic.com/v1/messages",
            "claude-sonnet-4-5",
            RequiresApiKey: true,
            "Uses an official Anthropic Console API key (sk-ant-api...). Claude Free/Pro/Max OAuth tokens (sk-ant-oat...) are blocked; use official Claude Code with Axiom's read-only MCP server instead."),
        new(
            AiProviderKind.GoogleGemini,
            "Google Gemini (Official AI Studio API key)",
            "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            "gemini-2.5-flash",
            RequiresApiKey: true,
            "Uses an official Google AI Studio API key (AIza...). Google OAuth tokens (ya29.) and private Antigravity/Gemini Code Assist endpoints are blocked; use official Antigravity or Gemini CLI with Axiom's read-only MCP server instead."),
        new(
            AiProviderKind.OpenRouter,
            "OpenRouter (Official API key — Claude, Gemini, GPT & more)",
            "https://openrouter.ai/api/v1/chat/completions",
            "google/gemini-2.5-flash",
            RequiresApiKey: true,
            "Uses an official OpenRouter API key over HTTPS with Axiom attribution headers for compliant multi-model access."),
        new(
            AiProviderKind.DeepSeek,
            "DeepSeek (Official API key)",
            "https://api.deepseek.com/chat/completions",
            "deepseek-chat",
            RequiresApiKey: true,
            "Uses an official DeepSeek API key over HTTPS against api.deepseek.com."),
        new(
            AiProviderKind.Zai,
            "Z.ai GLM (Official API key)",
            "https://api.z.ai/api/paas/v4/chat/completions",
            "glm-5.3",
            RequiresApiKey: true,
            "Uses an official Z.ai API key over HTTPS against api.z.ai."),
        new(
            AiProviderKind.OpenCodeZen,
            "OpenCode Zen (Official API key)",
            "https://opencode.ai/zen/v1/chat/completions",
            "deepseek-v4.1-flash",
            RequiresApiKey: true,
            "Uses an official OpenCode Zen API key over HTTPS against opencode.ai."),
        new(
            AiProviderKind.OpenAiCompatible,
            "Custom HTTPS OpenAI-compatible API (BYOK)",
            string.Empty,
            string.Empty,
            RequiresApiKey: true,
            "Bring-your-own HTTPS OpenAI-compatible API endpoint and key. Subscription OAuth tokens (sk-ant-oat..., ya29....) are rejected for every provider, known consumer web and private OAuth backend hosts are blocked, and redirects are not followed."),
        new(
            AiProviderKind.OpenChamberLocal,
            "OpenCode CLI (local — authorized OpenCode providers only)",
            "opencode://local",
            "opencode-go/deepseek-v4.1-flash",
            RequiresApiKey: false,
            "Runs local OpenCode CLI with authorized OpenCode providers only (for example opencode-go, ollama, lmstudio, deepseek, or openrouter). Third-party subscription OAuth providers, including openai/* (which OpenCode can sign in with a ChatGPT subscription), and :free external routes are blocked; use the OpenAI Platform API key preset instead."),
    ];

    private static readonly (string Domain, string Description)[] BlockedEndpointDomains =
    [
        ("cloudcode-pa.googleapis.com", "Google Antigravity / Gemini Code Assist private OAuth backend"),
        ("claude.ai", "Anthropic consumer web endpoint"),
        ("chatgpt.com", "OpenAI consumer web endpoint"),
        ("chat.openai.com", "OpenAI consumer web endpoint"),
        ("api.githubcopilot.com", "GitHub Copilot internal proxy"),
        ("copilot-proxy.githubusercontent.com", "GitHub Copilot internal proxy"),
    ];

    private static readonly HashSet<string> BlockedOpenCodeProviders = new(StringComparer.Ordinal)
    {
        "anthropic",
        "claude",
        "claude-code",
        "antigravity",
        "google",
        "google-gemini-cli",
        "gemini",
        "gemini-cli",
        "vertex-antigravity",
        "github-copilot",
        "copilot",
        "chatgpt",
        "codex",
        "openai",
        "openai-codex",
        "cursor",
        "windsurf",
    };

    private static readonly string[] BlockedBareModelPrefixes =
    [
        "claude-",
        "antigravity",
        "gemini-cli",
    ];

    /// <summary>Returns all provider presets ordered with local and official API providers first.</summary>
    public static IReadOnlyList<AiProviderPreset> GetPresets() => Presets;

    /// <summary>Looks up preset metadata for <paramref name="kind"/>.</summary>
    public static bool TryGetPreset(AiProviderKind kind, [NotNullWhen(true)] out AiProviderPreset? preset)
    {
        foreach (var candidate in Presets)
        {
            if (candidate.Kind == kind)
            {
                preset = candidate;
                return true;
            }
        }

        preset = null;
        return false;
    }

    /// <summary>Returns the concise Terms-of-Service compliance note for <paramref name="kind"/>.</summary>
    public static string GetComplianceNote(AiProviderKind kind) =>
        TryGetPreset(kind, out var preset)
            ? preset.ComplianceNote
            : "Use an official API key provider, local loopback model, or Axiom's read-only MCP server with your official CLI.";

    /// <summary>
    /// Validates that the configured provider, endpoint, credential prefix, and OpenCode model selection
    /// comply with provider Terms of Service.
    /// </summary>
    public static bool ValidateRequest(AiAnalystSettings settings, string? apiKey, out string error)
    {
        ArgumentNullException.ThrowIfNull(settings);

        if (!string.IsNullOrWhiteSpace(settings.Endpoint) &&
            Uri.TryCreate(settings.Endpoint.Trim(), UriKind.Absolute, out var endpointUri) &&
            (endpointUri.Scheme == Uri.UriSchemeHttp || endpointUri.Scheme == Uri.UriSchemeHttps))
        {
            var host = endpointUri.Host.TrimEnd('.');
            foreach (var (domain, description) in BlockedEndpointDomains)
            {
                if (IsHostOrSubdomain(host, domain))
                {
                    error =
                        $"Endpoint host '{host}' ({description}) is blocked for ToS compliance. " +
                        "Use an official API key provider (Anthropic Console, Google AI Studio, OpenAI Platform, or OpenRouter), " +
                        "a local Ollama/LM Studio model, or connect your official CLI to Axiom's read-only MCP server.";
                    return false;
                }
            }
        }

        // Subscription OAuth tokens are never valid platform API keys, so they are rejected for
        // every provider kind and endpoint, including custom and local OpenAI-compatible relays.
        var trimmedKey = apiKey?.Trim() ?? string.Empty;
        if (trimmedKey.StartsWith("sk-ant-oat", StringComparison.OrdinalIgnoreCase))
        {
            error =
                "Claude Pro/Max/Claude Code OAuth tokens (sk-ant-oat...) violate Anthropic ToS in third-party apps, with any provider or endpoint. " +
                "Use an Anthropic Console API key (sk-ant-api...) or official Claude Code with Axiom's read-only MCP server.";
            return false;
        }

        if (trimmedKey.StartsWith("ya29.", StringComparison.OrdinalIgnoreCase))
        {
            error =
                "Google OAuth tokens (ya29... from Antigravity / Gemini CLI) violate Google ToS in third-party apps, with any provider or endpoint. " +
                "Use a Google AI Studio API key (AIza...) or official Antigravity / Gemini CLI with Axiom's read-only MCP server.";
            return false;
        }

        if (settings.Provider == AiProviderKind.OpenChamberLocal)
        {
            if (!ValidateOpenCodeModel(settings.Model, out error))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(settings.VerifierModel) &&
                !ValidateOpenCodeModel(settings.VerifierModel, out error))
            {
                return false;
            }

            error = string.Empty;
            return true;
        }

        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Validates an OpenCode local model identifier to prevent piggybacking third-party consumer OAuth
    /// subscriptions or external-routing-restricted free-tier routes.
    /// </summary>
    public static bool ValidateOpenCodeModel(string? model, out string error)
    {
        if (string.IsNullOrWhiteSpace(model))
        {
            error = "OpenCode model is required.";
            return false;
        }

        var normalized = model.Trim().ToLowerInvariant();
        var slashIndex = normalized.IndexOf('/');
        if (slashIndex >= 0)
        {
            var provider = normalized[..slashIndex].Trim();
            if (BlockedOpenCodeProviders.Contains(provider))
            {
                error = BuildOpenCodeBlockedMessage(
                    $"OpenCode provider '{provider}' is blocked to protect your subscription account from ToS suspension.");
                return false;
            }
        }
        else
        {
            foreach (var prefix in BlockedBareModelPrefixes)
            {
                if (normalized.StartsWith(prefix, StringComparison.Ordinal))
                {
                    error = BuildOpenCodeBlockedMessage(
                        $"Bare OpenCode model '{model.Trim()}' is blocked to protect your subscription account from ToS suspension.");
                    return false;
                }
            }
        }

        if (normalized.EndsWith(":free", StringComparison.Ordinal) ||
            string.Equals(normalized, "free", StringComparison.Ordinal) ||
            normalized.StartsWith("opencode/free", StringComparison.Ordinal))
        {
            error = BuildOpenCodeBlockedMessage(
                $"OpenCode free-tier external route '{model.Trim()}' is blocked to protect your account from ToS suspension.");
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static bool IsHostOrSubdomain(string host, string domain) =>
        host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);

    private static string BuildOpenCodeBlockedMessage(string reason) =>
        $"{reason} Use an authorized OpenCode provider (such as opencode-go/*, ollama/*, lmstudio/*, deepseek/*, or openrouter/*), " +
        "configure an official API key provider (Anthropic, Google Gemini, OpenAI, or OpenRouter), " +
        "or connect your official CLI to Axiom's read-only MCP server.";
}
