// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Axiom.Presentation;

/// <summary>
/// Installs the Axiom five-event lifecycle bridge in <c>~/.codex/hooks.json</c>. Existing hooks are
/// merged, never replaced. Codex still requires the user to trust the exact hook definitions; this
/// class reports that trust state but never grants it.
/// </summary>
public sealed class CodexProtection
{
    private const string Marker = "axiom-codex-hook.py";

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

    public CodexProtection(string? userProfile = null, string? localAppData = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    public string ConfigDirectory => Path.Combine(_userProfile, ".codex");

    public string HooksPath => Path.Combine(ConfigDirectory, "hooks.json");

    public string ConfigPath => Path.Combine(ConfigDirectory, "config.toml");

    private string BlackboxAgentRoot => Path.Combine(
        _localAppData,
        "Axiom",
        "modules",
        "blackbox",
        "agent-blackbox");

    private string PythonPath => AgentPlatform.VenvPython(BlackboxAgentRoot);

    public string HookScriptPath => Path.Combine(BlackboxAgentRoot, Marker);

    private string ManagedCommand =>
        $"\"{PythonPath}\" \"{HookScriptPath}\" --bridge-version {AgentHookScript.Version}";

    private string BaseManagedCommand => $"\"{PythonPath}\" \"{HookScriptPath}\"";

    public bool IsCodexDetected =>
        Directory.Exists(ConfigDirectory) ||
        File.Exists(HooksPath) ||
        AgentBinaryLocator.IsCodexAvailable();

    public bool IsInstalled => File.Exists(PythonPath) && File.Exists(HookScriptPath) && HasAllHookEntries();

    public CodexTrustState TrustState =>
        new CodexTrustInspector(HooksPath, ConfigPath, ManagedCommand, HookScriptPath).Inspect();

    public bool EnsureInstalled()
    {
        if (!IsCodexDetected || !File.Exists(PythonPath))
        {
            return false;
        }

        try
        {
            if (StorageSafety.IsReparsePointInPath(ConfigDirectory) ||
                StorageSafety.IsReparsePointInPath(HooksPath) ||
                StorageSafety.IsReparsePointInPath(HookScriptPath))
            {
                return false;
            }

            DeleteLegacyScripts();
            var script = AgentHookScript.Build("codex");
            if (!File.Exists(HookScriptPath) || File.ReadAllText(HookScriptPath) != script)
            {
                File.WriteAllText(HookScriptPath, script, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }

            return MergeHookEntries();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    public void Remove()
    {
        try
        {
            if (StorageSafety.IsReparsePointInPath(HookScriptPath) ||
                StorageSafety.IsReparsePointInPath(HooksPath))
            {
                return;
            }

            if (File.Exists(HookScriptPath))
            {
                File.Delete(HookScriptPath);
            }

            DeleteLegacyScripts();

            if (!File.Exists(HooksPath))
            {
                return;
            }

            var root = JsonNode.Parse(File.ReadAllText(HooksPath)) as JsonObject;
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
                // No Axiom-owned hook was present; leave the user's file byte-identical.
                return;
            }

            if (hooks.Count == 0)
            {
                root.Remove("hooks");
            }

            StorageSafety.BackupFile(HooksPath);
            File.WriteAllText(
                HooksPath,
                root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
        }
    }

    private bool HasAllHookEntries()
    {
        try
        {
            if (!File.Exists(HooksPath))
            {
                return false;
            }

            var root = JsonNode.Parse(File.ReadAllText(HooksPath)) as JsonObject;
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
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    private bool IsOwnedHandler(JsonObject handler)
    {
        var command = ReadString(handler, "command");
        var commandWindows = ReadString(handler, "commandWindows");
        if (LegacyHookIdentity.IsLegacyCommand(command) ||
            LegacyHookIdentity.IsLegacyCommand(commandWindows))
        {
            return true;
        }

        return string.Equals(command, ManagedCommand, StringComparison.OrdinalIgnoreCase) ||
               string.Equals(command, BaseManagedCommand, StringComparison.OrdinalIgnoreCase) ||
               string.Equals(commandWindows, ManagedCommand, StringComparison.OrdinalIgnoreCase) ||
               string.Equals(commandWindows, BaseManagedCommand, StringComparison.OrdinalIgnoreCase);
    }

    private bool IsCurrentHandler(JsonObject handler) =>
        IsOwnedHandler(handler) &&
        handler["timeout"] is JsonValue timeoutValue &&
        timeoutValue.TryGetValue<int>(out var timeout) &&
        timeout == 30 &&
        string.Equals(ReadString(handler, "commandWindows") ?? ReadString(handler, "command"),
            ManagedCommand, StringComparison.OrdinalIgnoreCase);

    private bool MergeHookEntries()
    {
        if (HasAllHookEntries())
        {
            return true;
        }

        JsonObject root;
        if (File.Exists(HooksPath))
        {
            if (JsonNode.Parse(File.ReadAllText(HooksPath)) is not JsonObject existing)
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
                    }
                }

                if (handlers.Count == 0)
                {
                    groups.RemoveAt(index);
                }
            }

            groups.Add(BuildGroup(matcher, status));
        }

        Directory.CreateDirectory(ConfigDirectory);
        StorageSafety.BackupFile(HooksPath);
        File.WriteAllText(
            HooksPath,
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
            ["command"] = ManagedCommand,
            ["commandWindows"] = ManagedCommand,
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

    private static string? ReadString(JsonObject? node, string propertyName) =>
        node?[propertyName] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;
}
