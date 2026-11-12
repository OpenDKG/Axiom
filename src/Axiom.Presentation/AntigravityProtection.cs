// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Axiom.Presentation;

/// <summary>
/// Installs the Axiom guard as an Antigravity lifecycle hook. Antigravity reads global hooks from
/// <c>~/.gemini/config/hooks.json</c> and expects <c>{"decision":"allow|deny"}</c> on stdout, so a
/// small wrapper translates the shared Blackbox bridge result into that shape. The user file is
/// merged, never replaced.
/// </summary>
public sealed class AntigravityProtection
{
    private const string Marker = "axiom-antigravity-hook.py";

    private const string HookName = "axiom-guard";

    private readonly string _userProfile;

    private readonly string _localAppData;

    public AntigravityProtection(string? userProfile = null, string? localAppData = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    public string ConfigDirectory => Path.Combine(_userProfile, ".gemini", "config");

    public string HooksPath => Path.Combine(ConfigDirectory, "hooks.json");

    private string BlackboxAgentRoot => Path.Combine(
        _localAppData,
        "Axiom",
        "modules",
        "blackbox",
        "agent-blackbox");

    private string PythonPath => Path.Combine(BlackboxAgentRoot, "venv", "Scripts", "python.exe");

    public string HookScriptPath => Path.Combine(BlackboxAgentRoot, Marker);

    public bool IsAntigravityDetected =>
        Directory.Exists(Path.Combine(_userProfile, ".gemini")) ||
        File.Exists(HooksPath) ||
        File.Exists(Path.Combine(_localAppData, "Programs", "antigravity", "Antigravity.exe"));

    public bool IsInstalled =>
        File.Exists(PythonPath) && File.Exists(HookScriptPath) && HasOwnedHook();

    public bool EnsureInstalled()
    {
        if (!IsAntigravityDetected || !File.Exists(PythonPath))
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

            var script = BuildScript();
            if (!File.Exists(HookScriptPath) || File.ReadAllText(HookScriptPath) != script)
            {
                File.WriteAllText(
                    HookScriptPath,
                    script,
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }

            return MergeHook();
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
            if (StorageSafety.IsReparsePointInPath(HooksPath) ||
                StorageSafety.IsReparsePointInPath(HookScriptPath))
            {
                return;
            }

            if (File.Exists(HookScriptPath))
            {
                File.Delete(HookScriptPath);
            }

            if (!File.Exists(HooksPath))
            {
                return;
            }

            var root = JsonNode.Parse(File.ReadAllText(HooksPath)) as JsonObject;
            if (root?.Remove(HookName) == true)
            {
                File.WriteAllText(HooksPath, root.ToJsonString(JsonOptions), Encoding.UTF8);
            }
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
        {
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
    };

    private bool MergeHook()
    {
        JsonObject root;
        if (File.Exists(HooksPath))
        {
            root = JsonNode.Parse(File.ReadAllText(HooksPath)) as JsonObject
                   ?? throw new JsonException("Antigravity hooks.json is not an object.");
        }
        else
        {
            Directory.CreateDirectory(ConfigDirectory);
            root = [];
        }

        var command = $"\"{PythonPath}\" \"{HookScriptPath}\"";
        root[HookName] = new JsonObject
        {
            ["PreToolUse"] = new JsonArray
            {
                new JsonObject
                {
                    ["matcher"] = "*",
                    ["hooks"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["type"] = "command",
                            ["command"] = command,
                            ["timeout"] = 30,
                        },
                    },
                },
            },
        };

        File.WriteAllText(HooksPath, root.ToJsonString(JsonOptions), Encoding.UTF8);
        return true;
    }

    private bool HasOwnedHook()
    {
        try
        {
            if (!File.Exists(HooksPath))
            {
                return false;
            }

            var root = JsonNode.Parse(File.ReadAllText(HooksPath)) as JsonObject;
            if (root?[HookName]?["PreToolUse"] is not JsonArray groups)
            {
                return false;
            }

            foreach (var group in groups)
            {
                if (group?["hooks"] is JsonArray handlers &&
                    handlers.Any(handler =>
                        handler?["command"]?.GetValue<string>()?.Contains(Marker, StringComparison.OrdinalIgnoreCase) == true))
                {
                    return true;
                }
            }

            return false;
        }
        catch (Exception exception) when (exception is IOException or JsonException)
        {
            return false;
        }
    }

    private static string BuildScript() => """
        # Managed by Axiom. Antigravity PreToolUse hook: asks the Blackbox guard and
        # translates its decision into Antigravity's {"decision": ...} shape.
        import json
        import os
        import subprocess
        import sys
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent
        BRIDGE = ROOT / "axiom-guard-bridge.py"


        def main() -> None:
            try:
                payload = json.load(sys.stdin)
                tool_call = payload.get("toolCall") or {}
                request = {
                    "framework": "antigravity",
                    "event": "tool_call",
                    "tool": str(tool_call.get("name") or ""),
                    "args": tool_call.get("args") or {},
                    "session": str(payload.get("conversationId") or ""),
                    "call": str(payload.get("stepIdx") if payload.get("stepIdx") is not None else ""),
                    "workspace": ",".join(payload.get("workspacePaths") or []),
                }
                completed = subprocess.run(
                    [sys.executable, str(BRIDGE)],
                    input=json.dumps(request),
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                try:
                    decision = json.loads((completed.stdout or "").strip() or "{}")
                except Exception:
                    decision = {}
                if str(decision.get("action") or "").lower() == "block":
                    print(json.dumps({
                        "decision": "deny",
                        "reason": str(decision.get("reason") or "Blocked by the Axiom guard"),
                    }))
                else:
                    print(json.dumps({"decision": "allow"}))
            except Exception:
                # Fail open, like the other Axiom hooks: a guard fault must not break the host agent.
                print(json.dumps({"decision": "allow"}))


        if __name__ == "__main__":
            main()
        """;
}
