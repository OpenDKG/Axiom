// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;

namespace Axiom.Core.Enforcement;

/// <summary>Host harnesses Axiom provisions a hook for.</summary>
public enum HostHarness
{
    Unknown = 0,
    OpenCode = 1,
    ClaudeCode = 2,
    Codex = 3,
    Cursor = 4,
    Copilot = 5,
    Gemini = 6,
    Windsurf = 7,
    Cline = 8,
    ZCode = 9,
    DeepSeek = 10,
}

/// <summary>
/// Portable translation between host hook events and the policy engine. It builds the typed request
/// and the host-specific deny payload; it does not run hooks, call Blackbox or change host files.
/// </summary>
/// <remarks>
/// The deny shapes mirror the current shared hook script: Codex takes
/// <c>{"decision":"block","reason":...}</c>, every other host takes the Claude-style
/// <c>hookSpecificOutput</c> object. Only a <see cref="EnforcementDecision.Block"/> produces a
/// payload: <c>Ask</c>, <c>Audit</c> and <c>Unavailable</c> must never be turned into a pretend deny.
/// </remarks>
public static class HostDecisionMapping
{
    public const string PreToolUseEvent = "PreToolUse";

    public const string DefaultBlockMessage = "Blocked by Axiom policy.";

    private static readonly HashSet<string> DeleteTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "delete", "delete_file", "remove", "rm", "unlink",
    };

    private static readonly HashSet<string> WriteTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "write", "write_file", "edit", "apply_patch", "patch", "create_file", "str_replace_editor",
    };

    private static readonly HashSet<string> ReadTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "read", "read_file", "view", "open_file", "cat", "list_directory", "grep", "search_files",
    };

    private static readonly HashSet<string> ExecuteTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "bash", "shell", "exec", "execute", "run", "terminal", "command", "powershell",
    };

    private static readonly HashSet<string> HttpTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "webfetch", "web_fetch", "fetch", "http", "http_request", "browser",
    };

    private static readonly HashSet<string> NetworkTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "connect", "network", "socket", "ssh", "scp",
    };

    /// <summary>Maps a host tool name to the action kind the policy engine understands.</summary>
    public static AgentActionKind MapToolKind(string? toolName)
    {
        if (string.IsNullOrWhiteSpace(toolName))
        {
            return AgentActionKind.ToolCall;
        }

        var name = toolName.Trim();
        if (DeleteTools.Contains(name))
        {
            return AgentActionKind.DeleteFile;
        }

        if (WriteTools.Contains(name))
        {
            return AgentActionKind.WriteFile;
        }

        if (ReadTools.Contains(name))
        {
            return AgentActionKind.ReadFile;
        }

        if (ExecuteTools.Contains(name))
        {
            return AgentActionKind.ExecuteProcess;
        }

        if (HttpTools.Contains(name))
        {
            return AgentActionKind.HttpRequest;
        }

        return NetworkTools.Contains(name) ? AgentActionKind.NetworkConnect : AgentActionKind.ToolCall;
    }

    /// <summary>Builds the typed request a host hook would evaluate.</summary>
    public static AgentActionRequest MapRequest(
        string requestId,
        string agentId,
        string? sessionId,
        string? toolName,
        string? target,
        string? processPath,
        DateTimeOffset utcTime) => new()
        {
            RequestId = requestId,
            AgentId = agentId,
            SessionId = sessionId,
            Kind = MapToolKind(toolName),
            Target = target,
            ProcessPath = processPath,
            UtcTime = utcTime,
        };

    /// <summary>
    /// Returns the host-specific deny payload, or <c>null</c> when the verdict is not a block. A
    /// caller must send this payload only on hosts whose deny contract is verified; the payload
    /// itself carries no strength claim.
    /// </summary>
    public static string? ToHostResponse(
        HostHarness host,
        AgentActionVerdict verdict,
        string? message = null)
    {
        ArgumentNullException.ThrowIfNull(verdict);

        if (verdict.Decision != EnforcementDecision.Block)
        {
            return null;
        }

        var reason = string.IsNullOrWhiteSpace(message) ? DefaultBlockMessage : message;

        return host == HostHarness.Codex
            ? JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["decision"] = "block",
                ["reason"] = reason,
            })
            : JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["hookSpecificOutput"] = new Dictionary<string, string>
                {
                    ["hookEventName"] = PreToolUseEvent,
                    ["permissionDecision"] = "deny",
                    ["permissionDecisionReason"] = reason,
                },
            });
    }
}
