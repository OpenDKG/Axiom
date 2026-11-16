// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiom.Contracts.Blackbox;

namespace Axiom.UI.Services;

/// <summary>
/// Installs a Gemini CLI <c>BeforeTool</c> hook in the user's ~/.gemini/settings.json. Antigravity
/// history and MCP files are never touched; detection requires the Gemini settings file rather
/// than the shared ~/.gemini directory alone.
/// </summary>
public sealed class GeminiProtection
{
    private const string Marker = "axiom-gemini-hook.py";

    private readonly string _userProfile;

    private readonly string _localAppData;

    public GeminiProtection(string? userProfile = null, string? localAppData = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    public string ConfigDirectory => Path.Combine(_userProfile, ".gemini");

    public string SettingsPath => Path.Combine(ConfigDirectory, "settings.json");

    private string BlackboxAgentRoot => Path.Combine(
        _localAppData,
        "Axiom",
        "modules",
        "blackbox",
        "agent-blackbox");

    private string PythonPath => Path.Combine(BlackboxAgentRoot, "venv", "Scripts", "python.exe");

    public string HookScriptPath => Path.Combine(BlackboxAgentRoot, Marker);

    private string ManagedCommand => $"\"{PythonPath}\" \"{HookScriptPath}\"";

    public bool IsGeminiDetected => File.Exists(SettingsPath) || AgentBinaryLocator.IsGeminiAvailable();

    public bool IsInstalled => File.Exists(HookScriptPath) && HasHookEntry();

    public bool EnsureInstalled()
    {
        if (!IsGeminiDetected || !File.Exists(PythonPath))
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

            var script = BuildHookScript();
            if (!File.Exists(HookScriptPath) || File.ReadAllText(HookScriptPath) != script)
            {
                File.WriteAllText(
                    HookScriptPath,
                    script,
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }

            return MergeHookEntry();
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

            if (!File.Exists(SettingsPath))
            {
                return;
            }

            var root = JsonNode.Parse(File.ReadAllText(SettingsPath)) as JsonObject;
            if (root?["hooks"] is not JsonObject hooks ||
                hooks["BeforeTool"] is not JsonArray groups)
            {
                return;
            }

            var removed = false;
            for (var index = groups.Count - 1; index >= 0; index--)
            {
                if (groups[index] is not JsonObject group ||
                    group["hooks"] is not JsonArray handlers)
                {
                    continue;
                }

                for (var handlerIndex = handlers.Count - 1; handlerIndex >= 0; handlerIndex--)
                {
                    if (handlers[handlerIndex] is JsonObject handler &&
                        handler["command"]?.ToString().Contains(Marker, StringComparison.Ordinal) == true)
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

            if (!removed)
            {
                return;
            }

            if (groups.Count == 0)
            {
                hooks.Remove("BeforeTool");
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

    private bool HasHookEntry()
    {
        try
        {
            if (!File.Exists(SettingsPath))
            {
                return false;
            }

            var root = JsonNode.Parse(File.ReadAllText(SettingsPath)) as JsonObject;
            return root?["hooks"] is JsonObject hooks &&
                   hooks["BeforeTool"] is JsonArray groups &&
                   groups.OfType<JsonObject>().Any(group =>
                       group["hooks"] is JsonArray handlers &&
                       handlers.OfType<JsonObject>().Any(IsOwnedHandler));
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    private bool IsOwnedHandler(JsonObject handler) =>
        handler["command"] is JsonValue value &&
        value.TryGetValue<string>(out var command) &&
        (string.Equals(command, ManagedCommand, StringComparison.OrdinalIgnoreCase) ||
         LegacyHookIdentity.IsLegacyCommand(command));

    private bool MergeHookEntry()
    {
        var root = File.Exists(SettingsPath)
            ? JsonNode.Parse(File.ReadAllText(SettingsPath)) as JsonObject
            : new JsonObject();
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

        if (hooks["BeforeTool"] is not null && hooks["BeforeTool"] is not JsonArray)
        {
            return false;
        }

        if (hooks["BeforeTool"] is not JsonArray groups)
        {
            groups = new JsonArray();
            hooks["BeforeTool"] = groups;
        }

        if (HasHookEntry())
        {
            return true;
        }

        groups.Add(new JsonObject
        {
            ["matcher"] = "*",
            ["hooks"] = new JsonArray
            {
                new JsonObject
                {
                    ["name"] = "axiom-guard",
                    ["type"] = "command",
                    ["command"] = ManagedCommand,
                    ["timeout"] = 10000,
                },
            },
        });

        StorageSafety.BackupFile(SettingsPath);
        Directory.CreateDirectory(ConfigDirectory);
        File.WriteAllText(
            SettingsPath,
            root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return true;
    }

    private static string BuildHookScript() => """
        # Managed by Axiom. Calls the local Blackbox guard for Gemini CLI BeforeTool hooks.
        import contextlib
        import datetime
        import json
        import os
        import sys
        import time
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent
        sys.path.insert(0, str(ROOT))
        EVIDENCE = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Axiom" / "agent-evidence.jsonl"


        # <<AXIOM_COMMAND_GUARD>>


        def record(event_type, tool, decision, guard_status, duration_ms, error_code=""):
            try:
                EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
                if EVIDENCE.exists() and EVIDENCE.stat().st_size > 1_000_000:
                    lines = EVIDENCE.read_text(encoding="utf-8").splitlines()[-500:]
                    EVIDENCE.write_text("\n".join(lines) + "\n", encoding="utf-8")
                entry = {
                    "timestampUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "framework": "gemini",
                    "eventType": event_type,
                    "tool": tool,
                    "decision": decision,
                    "guardStatus": guard_status,
                    "durationMs": duration_ms,
                    "errorCode": error_code,
                }
                with EVIDENCE.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry) + "\n")
            except Exception:
                pass


        def main() -> None:
            started = time.monotonic()
            tool = ""
            try:
                payload = json.load(sys.stdin)
                tool = str(payload.get("tool_name", ""))
                raw_args = payload.get("tool_input")
                parsed_args = dict(raw_args) if isinstance(raw_args, dict) else {}
                # Gemini's read_file passes absolute_path; the vendor guard reads path.
                if not parsed_args.get("path") and isinstance(parsed_args.get("absolute_path"), str):
                    parsed_args["path"] = parsed_args["absolute_path"]
                safety = _check_command_safety(parsed_args, _load_protected_paths())
                if safety is not None:
                    record(
                        "GUARD_BLOCKED",
                        tool,
                        "block",
                        "blocked",
                        int((time.monotonic() - started) * 1000),
                        error_code=safety[0])
                    print(json.dumps({
                        "decision": "deny",
                        "reason": safety[1],
                    }))
                    return
                with contextlib.redirect_stdout(sys.stderr):
                    from plugins.blackbox.guard.hooks import on_pre_tool_call

                    decision = on_pre_tool_call(
                        tool_name=tool,
                        args=parsed_args,
                        session_id=str(payload.get("session_id", "")),
                        tool_call_id=str(payload.get("tool_use_id", "")),
                    )
                blocked = bool(decision and decision.get("action") == "block")
                record(
                    "GUARD_BLOCKED" if blocked else "GUARD_ALLOWED",
                    tool,
                    "block" if blocked else "allowed",
                    "blocked" if blocked else "allowed",
                    int((time.monotonic() - started) * 1000))
                if blocked:
                    print(json.dumps({
                        "decision": "deny",
                        "reason": decision.get("message") or "Blocked by Axiom/Blackbox",
                    }))
            except Exception as exc:
                # Fail open: a Blackbox or hook fault must not break Gemini CLI.
                record("GUARD_FAILED", tool, "", "error",
                       int((time.monotonic() - started) * 1000), type(exc).__name__)


        if __name__ == "__main__":
            main()
        """.Replace("# <<AXIOM_COMMAND_GUARD>>", AgentCommandGuard.PythonHelpers, StringComparison.Ordinal);
}
