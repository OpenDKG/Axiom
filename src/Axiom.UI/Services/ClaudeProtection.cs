// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Axiom.UI.Services;

/// <summary>
/// Installs the Axiom lifecycle bridge in the user's <c>~/.claude/settings.json</c>. The user
/// settings file is merged, never replaced, and unrelated hooks/settings are preserved.
/// </summary>
public sealed class ClaudeProtection
{
    private const string Marker = "axiom-claude-hook.py";

    private static readonly (string Name, bool Matcher, string? Status)[] HookEvents =
    [
        ("SessionStart", true, "Starting Axiom guard"),
        ("UserPromptSubmit", false, "Scanning prompt with Axiom"),
        ("PreToolUse", true, "Checking tool call with Axiom"),
        ("PostToolUse", true, null),
        ("Stop", false, null),
    ];

    private readonly string _userProfile;

    private readonly string _localAppData;

    public ClaudeProtection(string? userProfile = null, string? localAppData = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    public string ConfigDirectory => Path.Combine(_userProfile, ".claude");

    public string SettingsPath => Path.Combine(ConfigDirectory, "settings.json");

    private string BlackboxAgentRoot => Path.Combine(
        _localAppData,
        "Axiom",
        "modules",
        "blackbox",
        "agent-blackbox");

    private string PythonPath => Path.Combine(BlackboxAgentRoot, "venv", "Scripts", "python.exe");

    public string HookScriptPath => Path.Combine(BlackboxAgentRoot, Marker);

    public bool IsClaudeDetected =>
        Directory.Exists(ConfigDirectory) ||
        File.Exists(SettingsPath) ||
        AgentBinaryLocator.IsClaudeAvailable();

    public bool IsInstalled => File.Exists(PythonPath) && File.Exists(HookScriptPath) && HasAllHookEntries();

    public bool EnsureInstalled()
    {
        if (!IsClaudeDetected || !File.Exists(PythonPath))
        {
            return false;
        }

        try
        {
            if (StorageSafety.IsReparsePointInPath(ConfigDirectory) ||
                StorageSafety.IsReparsePointInPath(SettingsPath) ||
                StorageSafety.IsReparsePointInPath(HookScriptPath))
            {
                return false;
            }

            DeleteLegacyScripts();
            var script = AgentHookScript.Build("claude");
            if (!File.Exists(HookScriptPath) || File.ReadAllText(HookScriptPath) != script)
            {
                File.WriteAllText(
                    HookScriptPath,
                    script,
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }

            return MergeHookEntries();
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    public void Remove()
    {
        try
        {
            if (StorageSafety.IsReparsePointInPath(HookScriptPath) ||
                StorageSafety.IsReparsePointInPath(SettingsPath))
            {
                return;
            }

            if (File.Exists(HookScriptPath))
            {
                File.Delete(HookScriptPath);
            }

            DeleteLegacyScripts();

            if (!File.Exists(SettingsPath))
            {
                return;
            }

            var root = JsonNode.Parse(File.ReadAllText(SettingsPath)) as JsonObject;
            if (root?["hooks"] is not JsonObject hooks)
            {
                return;
            }

            var removed = false;
            foreach (var (eventName, _, _) in HookEvents)
            {
                if (hooks[eventName] is not JsonArray groups)
                {
                    continue;
                }

                for (var index = groups.Count - 1; index >= 0; index--)
                {
                    if (groups[index] is not JsonObject group ||
                        group["hooks"] is not JsonArray handlers)
                    {
                        continue;
                    }

                    for (var handlerIndex = handlers.Count - 1; handlerIndex >= 0; handlerIndex--)
                    {
                        if (handlers[handlerIndex] is JsonObject handler && IsOwnedHandler(handler))
                        {
                            handlers.RemoveAt(handlerIndex);
                            removed = true;
                        }
                    }

                    if (handlers.Count == 0)
                    {
                        groups.RemoveAt(index);
                    }
                }

                if (groups.Count == 0)
                {
                    hooks.Remove(eventName);
                }
            }

            if (!removed)
            {
                return;
            }

            if (hooks.Count == 0)
            {
                root.Remove("hooks");
            }

            StorageSafety.BackupFile(SettingsPath);
            File.WriteAllText(
                SettingsPath,
                root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
        {
        }
    }

    private bool HasAllHookEntries()
    {
        try
        {
            if (!File.Exists(SettingsPath))
            {
                return false;
            }

            var root = JsonNode.Parse(File.ReadAllText(SettingsPath)) as JsonObject;
            if (root?["hooks"] is not JsonObject hooks)
            {
                return false;
            }

            return HookEvents.All(hook =>
                hooks[hook.Name] is JsonArray groups &&
                groups.OfType<JsonObject>().Any(group =>
                    group["hooks"] is JsonArray handlers &&
                    handlers.OfType<JsonObject>().Any(IsCurrentHandler)));
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    private bool IsCurrentHandler(JsonObject handler) =>
        IsOwnedHandler(handler) &&
        handler["timeout"] is JsonValue timeoutValue &&
        timeoutValue.TryGetValue<int>(out var timeout) &&
        timeout == 30 &&
        handler["args"] is JsonArray args &&
        args.Count >= 3 &&
        args[1] is JsonValue versionFlag &&
        versionFlag.TryGetValue<string>(out var flag) &&
        string.Equals(flag, "--bridge-version", StringComparison.Ordinal) &&
        args[2] is JsonValue versionValue &&
        versionValue.TryGetValue<string>(out var version) &&
        string.Equals(version, AgentHookScript.Version, StringComparison.Ordinal);

    private bool IsOwnedHandler(JsonObject handler)
    {
        if (handler["command"] is not JsonValue commandValue ||
            !commandValue.TryGetValue<string>(out var command))
        {
            return false;
        }

        if (LegacyHookIdentity.IsLegacyCommand(command))
        {
            return true;
        }

        if (!string.Equals(command, PythonPath, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return handler["args"] is JsonArray args &&
               args.Count >= 1 &&
               args[0] is JsonValue scriptValue &&
               scriptValue.TryGetValue<string>(out var script) &&
               string.Equals(script, HookScriptPath, StringComparison.OrdinalIgnoreCase);
    }

    private bool MergeHookEntries()
    {
        if (HasAllHookEntries())
        {
            return true;
        }

        JsonObject root;
        if (File.Exists(SettingsPath))
        {
            if (JsonNode.Parse(File.ReadAllText(SettingsPath)) is not JsonObject existing)
            {
                return false;
            }

            root = existing;
        }
        else
        {
            root = new JsonObject();
        }

        if (root["hooks"] is not null && root["hooks"] is not JsonObject)
        {
            return false;
        }

        if (root["hooks"] is not JsonObject hooks)
        {
            hooks = new JsonObject();
            root["hooks"] = hooks;
        }

        var changed = false;
        foreach (var (eventName, matcher, status) in HookEvents)
        {
            if (hooks[eventName] is not null && hooks[eventName] is not JsonArray)
            {
                return false;
            }

            if (hooks[eventName] is not JsonArray groups)
            {
                groups = new JsonArray();
                hooks[eventName] = groups;
            }

            for (var index = groups.Count - 1; index >= 0; index--)
            {
                if (groups[index] is not JsonObject group ||
                    group["hooks"] is not JsonArray handlers)
                {
                    continue;
                }

                for (var handlerIndex = handlers.Count - 1; handlerIndex >= 0; handlerIndex--)
                {
                    if (handlers[handlerIndex] is JsonObject handler && IsOwnedHandler(handler))
                    {
                        handlers.RemoveAt(handlerIndex);
                        changed = true;
                    }
                }

                if (handlers.Count == 0)
                {
                    groups.RemoveAt(index);
                }
            }

            groups.Add(BuildGroup(matcher, status));
            changed = true;
        }

        if (!changed)
        {
            return HasAllHookEntries();
        }

        StorageSafety.BackupFile(SettingsPath);
        Directory.CreateDirectory(ConfigDirectory);
        File.WriteAllText(
            SettingsPath,
            root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return HasAllHookEntries();
    }

    private void DeleteLegacyScripts()
    {
        foreach (var path in new[]
                 {
                     Path.Combine(BlackboxAgentRoot, LegacyHookIdentity.ScriptName(Marker)),
                     Path.Combine(
                         _localAppData,
                         LegacyHookIdentity.DataDirectoryName,
                         "modules",
                         "blackbox",
                         "agent-blackbox",
                         LegacyHookIdentity.ScriptName(Marker)),
                 })
        {
            try
            {
                if (File.Exists(path) && !StorageSafety.IsReparsePointInPath(path))
                {
                    File.Delete(path);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }
    }

    private JsonObject BuildGroup(bool matcher, string? status)
    {
        var handler = new JsonObject
        {
            ["type"] = "command",
            ["command"] = PythonPath,
            ["args"] = new JsonArray(HookScriptPath, "--bridge-version", AgentHookScript.Version),
            ["timeout"] = 30,
        };
        if (status is not null)
        {
            handler["statusMessage"] = status;
        }

        var group = new JsonObject
        {
            ["hooks"] = new JsonArray(handler),
        };
        if (matcher)
        {
            group["matcher"] = "*";
        }

        return group;
    }
}
