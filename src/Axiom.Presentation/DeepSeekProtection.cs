// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Axiom.Presentation;

/// <summary>
/// Prepares the Axiom lifecycle hook file for DeepSeek Harness (DSH, <c>dsh</c> / <c>~/.dsh</c>)
/// and mounts DeepSeek's Claude Code hook bridge in the user-level <c>cordis.patch.yml</c>. DSH
/// does not read a hooks.json by itself, so the bridge package must be installed for the hook file
/// to run. Axiom never claims DSH is protected until both pieces are present, and skips plain
/// <c>deepseek-cli</c> installs that expose no lifecycle hook surface.
/// </summary>
public sealed class DeepSeekProtection
{
    private const string ManagedStatus = "Checking with Axiom";
    private const string PatchBegin = "# Axiom DeepSeek hook bridge (managed). Do not edit this block by hand.";
    private const string PatchEnd = "# End Axiom DeepSeek hook bridge.";

    private static readonly (string Name, bool Matcher)[] HookEvents =
    [
        ("SessionStart", false),
        ("UserPromptSubmit", false),
        ("PreToolUse", true),
        ("PostToolUse", true),
        ("Stop", false),
    ];

    private readonly string _userProfile;

    private readonly string _localAppData;

    private readonly string _dshHome;

    public DeepSeekProtection(
        string? userProfile = null,
        string? localAppData = null,
        string? dshHome = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _dshHome = dshHome ?? ResolveDshHome(_userProfile);
    }

    public string DshHome => _dshHome;

    public string HooksPath => Path.Combine(DshHome, "axiom-hooks.json");

    public string PatchPath => Path.Combine(DshHome, "cordis.patch.yml");

    private string BlackboxAgentRoot => Path.Combine(
        _localAppData,
        "Axiom",
        "modules",
        "blackbox",
        "agent-blackbox");

    private string PythonPath => Path.Combine(BlackboxAgentRoot, "venv", "Scripts", "python.exe");

    public string HookScriptPath => Path.Combine(BlackboxAgentRoot, "axiom-deepseek-hook.py");

    private string ManagedCommand => $"\"{PythonPath}\" \"{HookScriptPath}\"";

    public bool IsDeepSeekDetected =>
        Directory.Exists(DshHome) ||
        File.Exists(PatchPath) ||
        AgentBinaryLocator.IsDeepSeekAvailable();

    /// <summary>True when the hook file and bridge mount are present.</summary>
    public bool IsConfigured =>
        File.Exists(HooksPath) && HasAllHooks() && HasPatchBlock();

    /// <summary>True only when the bridge package is also installed in a DSH profile.</summary>
    public bool IsInstalled => IsConfigured && IsBridgeInstalled;

    public bool IsBridgeInstalled
    {
        get
        {
            try
            {
                foreach (var root in BridgeSearchRoots())
                {
                    if (File.Exists(Path.Combine(
                            root,
                            "node_modules",
                            "@deepseek-ai",
                            "dsh-hooks-claude-code",
                            "package.json")))
                    {
                        return true;
                    }
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }

            return false;
        }
    }

    public bool EnsureInstalled()
    {
        if (!IsDeepSeekDetected || !File.Exists(PythonPath))
        {
            return false;
        }

        try
        {
            if (StorageSafety.IsReparsePointInPath(DshHome) ||
                StorageSafety.IsReparsePointInPath(HooksPath) ||
                StorageSafety.IsReparsePointInPath(PatchPath) ||
                StorageSafety.IsReparsePointInPath(HookScriptPath))
            {
                return false;
            }

            var script = AgentHookScript.Build("deepseek");
            if (!File.Exists(HookScriptPath) || File.ReadAllText(HookScriptPath) != script)
            {
                File.WriteAllText(
                    HookScriptPath,
                    script,
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }

            var root = ReadHooks();
            if (root is null)
            {
                return false;
            }

            foreach (var (name, matcher) in HookEvents)
            {
                if (root[name] is not null && root[name] is not JsonArray)
                {
                    return false;
                }

                if (root[name] is not JsonArray groups)
                {
                    groups = new JsonArray();
                    root[name] = groups;
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
                    ["type"] = "command",
                    ["command"] = ManagedCommand,
                    ["timeout"] = 30,
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

            WriteHooks(root);
            EnsurePatchBlock();
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
            if (StorageSafety.IsReparsePointInPath(DshHome) ||
                StorageSafety.IsReparsePointInPath(HooksPath) ||
                StorageSafety.IsReparsePointInPath(PatchPath))
            {
                return;
            }

            if (File.Exists(HookScriptPath) &&
                !StorageSafety.IsReparsePointInPath(HookScriptPath))
            {
                File.Delete(HookScriptPath);
            }

            var root = ReadHooks();
            if (root is not null)
            {
                var removed = false;
                foreach (var (name, _) in HookEvents)
                {
                    if (root[name] is not JsonArray groups)
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
                        root.Remove(name);
                    }
                }

                if (removed)
                {
                    if (root.Count == 0)
                    {
                        File.Delete(HooksPath);
                    }
                    else
                    {
                        WriteHooks(root);
                    }
                }
            }

            RemovePatchBlock();
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
            var root = ReadHooks();
            return root is not null && HookEvents.All(hook =>
                root[hook.Name] is JsonArray groups &&
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

    private bool IsOwnedHandler(JsonObject handler) =>
        handler["type"] is JsonValue type &&
        type.TryGetValue<string>(out var typeName) &&
        string.Equals(typeName, "command", StringComparison.OrdinalIgnoreCase) &&
        handler["command"] is JsonValue command &&
        command.TryGetValue<string>(out var commandText) &&
        string.Equals(commandText, ManagedCommand, StringComparison.OrdinalIgnoreCase);

    private JsonObject? ReadHooks()
    {
        if (!File.Exists(HooksPath))
        {
            return new JsonObject();
        }

        return JsonNode.Parse(File.ReadAllText(HooksPath)) as JsonObject;
    }

    private void WriteHooks(JsonObject root)
    {
        Directory.CreateDirectory(DshHome);
        StorageSafety.BackupFile(HooksPath);
        File.WriteAllText(
            HooksPath,
            root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private void EnsurePatchBlock()
    {
        var block = BuildPatchBlock();
        var existing = File.Exists(PatchPath) ? File.ReadAllText(PatchPath) : string.Empty;
        var without = RemoveBlock(existing).TrimEnd();
        var combined = without.Length == 0
            ? block + Environment.NewLine
            : without + Environment.NewLine + Environment.NewLine + block + Environment.NewLine;
        Directory.CreateDirectory(DshHome);
        StorageSafety.BackupFile(PatchPath);
        File.WriteAllText(
            PatchPath,
            combined,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private void RemovePatchBlock()
    {
        if (!File.Exists(PatchPath))
        {
            return;
        }

        var existing = File.ReadAllText(PatchPath);
        var without = RemoveBlock(existing).TrimEnd();
        if (string.Equals(existing.TrimEnd(), without, StringComparison.Ordinal))
        {
            return;
        }

        if (without.Length == 0)
        {
            File.Delete(PatchPath);
            return;
        }

        StorageSafety.BackupFile(PatchPath);
        File.WriteAllText(
            PatchPath,
            without + Environment.NewLine,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private bool HasPatchBlock() =>
        File.Exists(PatchPath) &&
        File.ReadAllText(PatchPath).Contains(PatchBegin, StringComparison.Ordinal) &&
        File.ReadAllText(PatchPath).Contains(PatchEnd, StringComparison.Ordinal) &&
        File.ReadAllText(PatchPath).Contains(EscapeYaml(HooksPath), StringComparison.Ordinal);

    private string BuildPatchBlock() =>
        string.Join(
            Environment.NewLine,
            PatchBegin,
            "- insert:",
            "    - id: axiom-hooks",
            "      name: '@deepseek-ai/dsh-hooks-claude-code'",
            "      config:",
            $"        configPath: '{EscapeYaml(HooksPath)}'",
            PatchEnd);

    private static string RemoveBlock(string text)
    {
        var start = text.IndexOf(PatchBegin, StringComparison.Ordinal);
        if (start < 0)
        {
            return text;
        }

        var end = text.IndexOf(PatchEnd, start, StringComparison.Ordinal);
        if (end < 0)
        {
            return text;
        }

        end += PatchEnd.Length;
        return text[..start] + text[end..];
    }

    private static string EscapeYaml(string value) => value.Replace("'", "''", StringComparison.Ordinal);

    private IEnumerable<string> BridgeSearchRoots()
    {
        yield return DshHome;
        var profiles = Path.Combine(DshHome, "profiles");
        if (!Directory.Exists(profiles))
        {
            yield break;
        }

        foreach (var profile in Directory.EnumerateDirectories(profiles))
        {
            yield return profile;
        }
    }

    private static string ResolveDshHome(string userProfile)
    {
        var configured = Environment.GetEnvironmentVariable("DSH_HOME");
        return string.IsNullOrWhiteSpace(configured)
            ? Path.Combine(userProfile, ".dsh")
            : Path.GetFullPath(configured);
    }
}
