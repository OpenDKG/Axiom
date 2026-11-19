// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Axiom.Presentation;

/// <summary>
/// Installs the Axiom lifecycle bridge for ZCode's user-scope hook configuration at
/// <c>~/.zcode/cli/config.json</c>. Project-level hooks are ignored by ZCode and are never touched.
/// Existing user hooks and unrelated config keys are preserved.
/// </summary>
public sealed class ZCodeProtection
{
    private const string ManagedStatus = "Checking with Axiom";

    private static readonly (string Name, bool Matcher)[] HookEvents =
    [
        ("SessionStart", false),
        ("UserPromptSubmit", false),
        ("PreToolUse", false),
        ("PostToolUse", false),
        ("Stop", false),
    ];

    private readonly string _userProfile;

    private readonly string _localAppData;

    public ZCodeProtection(string? userProfile = null, string? localAppData = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    public string ConfigDirectory => Path.Combine(_userProfile, ".zcode");

    public string ConfigPath => Path.Combine(ConfigDirectory, "cli", "config.json");

    private string BlackboxAgentRoot => Path.Combine(
        _localAppData,
        "Axiom",
        "modules",
        "blackbox",
        "agent-blackbox");

    private string PythonPath => AgentPlatform.VenvPython(BlackboxAgentRoot);

    public string HookScriptPath => Path.Combine(BlackboxAgentRoot, "axiom-zcode-hook.py");

    public bool IsZCodeDetected =>
        Directory.Exists(ConfigDirectory) ||
        File.Exists(ConfigPath) ||
        AgentBinaryLocator.IsZCodeAvailable();

    public bool IsInstalled => File.Exists(HookScriptPath) && HasAllHooks();

    public bool EnsureInstalled()
    {
        if (!IsZCodeDetected || !File.Exists(PythonPath))
        {
            return false;
        }

        try
        {
            if (StorageSafety.IsReparsePointInPath(ConfigDirectory) ||
                StorageSafety.IsReparsePointInPath(ConfigPath) ||
                StorageSafety.IsReparsePointInPath(HookScriptPath))
            {
                return false;
            }

            var script = AgentHookScript.Build("zcode");
            if (!File.Exists(HookScriptPath) || File.ReadAllText(HookScriptPath) != script)
            {
                File.WriteAllText(
                    HookScriptPath,
                    script,
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }

            var root = ReadConfig();
            if (root is null)
            {
                return false;
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

            hooks["enabled"] = true;
            if (hooks["events"] is not null && hooks["events"] is not JsonObject)
            {
                return false;
            }

            if (hooks["events"] is not JsonObject events)
            {
                events = new JsonObject();
                hooks["events"] = events;
            }

            foreach (var (name, matcher) in HookEvents)
            {
                if (events[name] is not null && events[name] is not JsonArray)
                {
                    return false;
                }

                if (events[name] is not JsonArray groups)
                {
                    groups = new JsonArray();
                    events[name] = groups;
                }

                for (var index = groups.Count - 1; index >= 0; index--)
                {
                    if (groups[index] is JsonObject group && IsOwnedGroup(group))
                    {
                        groups.RemoveAt(index);
                    }
                }

                var handler = new JsonObject
                {
                    ["type"] = "process",
                    ["command"] = PythonPath,
                    ["args"] = new JsonArray(HookScriptPath),
                    ["timeoutMs"] = 30000,
                    ["statusMessage"] = ManagedStatus,
                };
                var newGroup = new JsonObject
                {
                    ["hooks"] = new JsonArray(handler),
                };
                if (matcher)
                {
                    newGroup["matcher"] = "*";
                }

                groups.Add(newGroup);
            }

            WriteConfig(root);
            return IsInstalled;
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
            if (StorageSafety.IsReparsePointInPath(ConfigDirectory) ||
                StorageSafety.IsReparsePointInPath(ConfigPath))
            {
                return;
            }

            if (File.Exists(HookScriptPath) &&
                !StorageSafety.IsReparsePointInPath(HookScriptPath))
            {
                File.Delete(HookScriptPath);
            }

            var root = ReadConfig();
            if (root?["hooks"] is not JsonObject hooks ||
                hooks["events"] is not JsonObject events)
            {
                return;
            }

            var removed = false;
            foreach (var (name, _) in HookEvents)
            {
                if (events[name] is not JsonArray groups)
                {
                    continue;
                }

                for (var index = groups.Count - 1; index >= 0; index--)
                {
                    if (groups[index] is JsonObject group && IsOwnedGroup(group))
                    {
                        groups.RemoveAt(index);
                        removed = true;
                    }
                }

                if (groups.Count == 0)
                {
                    events.Remove(name);
                }
            }

            if (!removed)
            {
                return;
            }

            if (events.Count == 0)
            {
                hooks.Remove("events");
            }

            WriteConfig(root);
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
        {
        }
    }

    private bool HasAllHooks()
    {
        try
        {
            var root = ReadConfig();
            if (root?["hooks"] is not JsonObject hooks ||
                !(hooks["enabled"] is JsonValue enabled && enabled.TryGetValue<bool>(out var isEnabled) && isEnabled) ||
                hooks["events"] is not JsonObject events)
            {
                return false;
            }

            return HookEvents.All(hook =>
                events[hook.Name] is JsonArray groups &&
                groups.OfType<JsonObject>().Any(IsOwnedGroup));
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    private bool IsOwnedGroup(JsonObject group) =>
        group["hooks"] is JsonArray handlers &&
        handlers.OfType<JsonObject>().Any(IsOwnedHandler);

    private bool IsOwnedHandler(JsonObject handler)
    {
        if (!(handler["type"] is JsonValue type && type.TryGetValue<string>(out var typeName)) ||
            !string.Equals(typeName, "process", StringComparison.OrdinalIgnoreCase) ||
            !(handler["command"] is JsonValue command && command.TryGetValue<string>(out var commandText)) ||
            !string.Equals(commandText, PythonPath, StringComparison.OrdinalIgnoreCase) ||
            handler["args"] is not JsonArray args)
        {
            return false;
        }

        return args.OfType<JsonValue>().Any(value =>
            value.TryGetValue<string>(out var arg) &&
            string.Equals(arg, HookScriptPath, StringComparison.OrdinalIgnoreCase));
    }

    private JsonObject? ReadConfig()
    {
        if (!File.Exists(ConfigPath))
        {
            return new JsonObject();
        }

        return JsonNode.Parse(File.ReadAllText(ConfigPath)) as JsonObject;
    }

    private void WriteConfig(JsonObject root)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
        StorageSafety.BackupFile(ConfigPath);
        File.WriteAllText(
            ConfigPath,
            root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }
}
