// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Axiom.UI.Services;

/// <summary>Result of reading Codex's own hook-trust state. Trust is never granted by Axiom.</summary>
public sealed record CodexTrustState(bool Installed, bool Trusted, string Detail)
{
    public bool TrustRequired => Installed && !Trusted;
}

/// <summary>
/// Reads the trust hashes Codex persists in <c>~/.codex/config.toml</c> and compares them with the
/// exact hook definitions Axiom installed. Codex still owns the approval; Axiom only reports
/// whether the current definitions are trusted.
/// </summary>
public sealed class CodexTrustInspector
{
    private static readonly (string Event, string Key, bool Matcher)[] Events =
    [
        ("SessionStart", "session_start", true),
        ("UserPromptSubmit", "user_prompt_submit", false),
        ("PreToolUse", "pre_tool_use", true),
        ("PostToolUse", "post_tool_use", true),
        ("Stop", "stop", false),
    ];

    private static readonly Regex StateSection = new(
        "^\\s*\\[hooks\\.state\\.(?<quote>['\"])(?<key>.*?)\\k<quote>\\]\\s*$",
        RegexOptions.Compiled);

    private static readonly Regex StateEvent = new(
        "hooks\\.json:(?<event>[a-z_]+):\\d+:\\d+$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly string _hooksPath;

    private readonly string _configPath;

    private readonly string? _ownedCommand;

    private readonly string? _ownedScriptPath;

    public CodexTrustInspector(string hooksPath, string configPath, string? ownedCommand = null, string? ownedScriptPath = null)
    {
        _hooksPath = hooksPath;
        _configPath = configPath;
        _ownedCommand = ownedCommand;
        _ownedScriptPath = ownedScriptPath;
    }

    public CodexTrustState Inspect()
    {
        if (!File.Exists(_hooksPath))
        {
            return new CodexTrustState(false, false, "Codex hook definitions are not installed.");
        }

        try
        {
            if (JsonNode.Parse(File.ReadAllText(_hooksPath)) is not JsonObject root)
            {
                return new CodexTrustState(false, false, "Codex hooks.json is not a JSON object.");
            }

            var hashes = CurrentHashes(root);
            if (hashes.Count != Events.Length)
            {
                return new CodexTrustState(
                    true,
                    false,
                    "Codex has only part of the Axiom lifecycle hook set. Reinstall the agent hooks.");
            }

            var state = ReadState(_configPath);
            var trusted = hashes.All(pair => state.Any(item =>
                string.Equals(item.Event, pair.Key, StringComparison.OrdinalIgnoreCase) &&
                item.Enabled &&
                string.Equals(item.Hash, pair.Value, StringComparison.OrdinalIgnoreCase)));

            return new CodexTrustState(
                true,
                trusted,
                trusted
                    ? "Codex trusts the current five lifecycle hook definitions."
                    : "Codex has not trusted the current hook definitions. Open Codex, run /hooks and trust the Axiom hooks.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new CodexTrustState(false, false, "Codex hook trust could not be read: " + exception.Message);
        }
    }

    internal static string ComputeHash(JsonObject group, JsonObject handler, string eventKey)
    {
        var command = ReadString(handler, "command") ?? string.Empty;
        if (OperatingSystem.IsWindows() &&
            ReadString(handler, "commandWindows") is { Length: > 0 } commandWindows)
        {
            command = commandWindows;
        }

        var timeout = ReadInt(handler, "timeout", 600);
        var statusMessage = ReadString(handler, "statusMessage");
        var additionalContextLimit = ReadInt(handler, "additionalContextLimit", 2500);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
               {
                   Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                   Indented = false,
               }))
        {
            writer.WriteStartObject();
            writer.WriteString("event_name", eventKey);
            writer.WritePropertyName("hooks");
            writer.WriteStartArray();
            writer.WriteStartObject();
            if (additionalContextLimit != 2500)
            {
                writer.WriteNumber("additionalContextLimit", additionalContextLimit);
            }

            writer.WriteBoolean("async", ReadBool(handler, "async"));
            writer.WriteString("command", command);
            if (statusMessage is not null)
            {
                writer.WriteString("statusMessage", statusMessage);
            }

            writer.WriteNumber("timeout", timeout);
            writer.WriteString("type", "command");
            writer.WriteEndObject();
            writer.WriteEndArray();
            if (MatcherEvent(eventKey) && ReadString(group, "matcher") is { } matcher)
            {
                writer.WriteString("matcher", matcher);
            }

            writer.WriteEndObject();
        }

        return "sha256:" + Convert.ToHexString(SHA256.HashData(stream.ToArray())).ToLowerInvariant();
    }

    private Dictionary<string, string> CurrentHashes(JsonObject root)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (root["hooks"] is not JsonObject hooks)
        {
            return result;
        }

        foreach (var (eventName, eventKey, _) in Events)
        {
            if (hooks[eventName] is not JsonArray groups)
            {
                continue;
            }

            foreach (var group in groups.OfType<JsonObject>())
            {
                if (group["hooks"] is not JsonArray handlers)
                {
                    continue;
                }

                foreach (var handler in handlers.OfType<JsonObject>())
                {
                    if (!IsOwnedHandler(handler))
                    {
                        continue;
                    }

                    result[eventKey] = ComputeHash(group, handler, eventKey);
                    break;
                }

                if (result.ContainsKey(eventKey))
                {
                    break;
                }
            }
        }

        return result;
    }

    private bool IsOwnedHandler(JsonObject handler)
    {
        var command = ReadString(handler, "command");
        if (command is null)
        {
            return false;
        }

        if (_ownedCommand is not null &&
            string.Equals(command, _ownedCommand, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return _ownedScriptPath is not null &&
               command.Contains(_ownedScriptPath, StringComparison.OrdinalIgnoreCase);
    }

    private static List<(string Event, string Hash, bool Enabled)> ReadState(string path)
    {
        var result = new List<(string Event, string Hash, bool Enabled)>();
        if (!File.Exists(path))
        {
            return result;
        }

        string? currentKey = null;
        string? currentHash = null;
        var enabled = true;

        void Flush()
        {
            if (currentKey is null || currentHash is null)
            {
                return;
            }

            var match = StateEvent.Match(currentKey);
            if (match.Success)
            {
                result.Add((match.Groups["event"].Value, currentHash, enabled));
            }
        }

        foreach (var rawLine in File.ReadLines(path))
        {
            var line = rawLine.Trim();
            var section = StateSection.Match(line);
            if (section.Success)
            {
                Flush();
                currentKey = section.Groups["key"].Value;
                currentHash = null;
                enabled = true;
                continue;
            }

            if (currentKey is null)
            {
                continue;
            }

            if (line.StartsWith("trusted_hash", StringComparison.Ordinal))
            {
                var assignment = line.IndexOf('=');
                if (assignment >= 0)
                {
                    currentHash = line[(assignment + 1)..].Trim().Trim('"');
                }
            }
            else if (line.StartsWith("enabled", StringComparison.Ordinal) &&
                     line.Contains("false", StringComparison.OrdinalIgnoreCase))
            {
                enabled = false;
            }
            else if (line.StartsWith('['))
            {
                Flush();
                currentKey = null;
                currentHash = null;
                enabled = true;
            }
        }

        Flush();
        return result;
    }

    private static bool MatcherEvent(string eventKey) =>
        eventKey is "session_start" or "pre_tool_use" or "post_tool_use";

    private static string? ReadString(JsonObject? node, string propertyName) =>
        node?[propertyName] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    private static int ReadInt(JsonObject? node, string propertyName, int fallback) =>
        node?[propertyName] is JsonValue value && value.TryGetValue<int>(out var number) ? number : fallback;

    private static bool ReadBool(JsonObject? node, string propertyName) =>
        node?[propertyName] is JsonValue value && value.TryGetValue<bool>(out var flag) && flag;
}
