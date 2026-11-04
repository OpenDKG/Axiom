// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Netpetra.UI.Services;

/// <summary>
/// Installs a Codex PreToolUse hook that calls the Blackbox guard. Codex stores user hooks in
/// <c>~/.codex/hooks.json</c>; the existing file is merged, never replaced.
/// </summary>
public sealed class CodexProtection
{
    private const string Marker = "netpetra-codex-hook.py";

    private readonly string _userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private readonly string _localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    public string ConfigDirectory => Path.Combine(_userProfile, ".codex");

    public string HooksPath => Path.Combine(ConfigDirectory, "hooks.json");

    private string BlackboxAgentRoot => Path.Combine(
        _localAppData,
        "Netpetra",
        "modules",
        "blackbox",
        "agent-blackbox");

    private string PythonPath => Path.Combine(BlackboxAgentRoot, "venv", "Scripts", "python.exe");

    public string HookScriptPath => Path.Combine(BlackboxAgentRoot, Marker);

    public bool IsCodexDetected => Directory.Exists(ConfigDirectory);

    public bool IsInstalled => File.Exists(HookScriptPath) && HasHookEntry();

    public bool EnsureInstalled()
    {
        if (!IsCodexDetected || !File.Exists(PythonPath))
        {
            return false;
        }

        try
        {
            if (StorageSafety.IsReparsePoint(ConfigDirectory) || StorageSafety.IsReparsePoint(HooksPath))
            {
                return false;
            }

            var script = BuildHookScript();
            if (!File.Exists(HookScriptPath) || File.ReadAllText(HookScriptPath) != script)
            {
                File.WriteAllText(HookScriptPath, script, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }

            return MergeHookEntry();
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
            if (File.Exists(HookScriptPath))
            {
                File.Delete(HookScriptPath);
            }

            if (!File.Exists(HooksPath))
            {
                return;
            }

            var root = JsonNode.Parse(File.ReadAllText(HooksPath)) as JsonObject;
            if (root?["hooks"] is not JsonObject hooks ||
                hooks["PreToolUse"] is not JsonArray groups)
            {
                return;
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
                    if (handlers[handlerIndex] is JsonObject handler &&
                        handler["command"]?.ToString().Contains(Marker, StringComparison.Ordinal) == true)
                    {
                        handlers.RemoveAt(handlerIndex);
                    }
                }

                if (handlers.Count == 0)
                {
                    groups.RemoveAt(index);
                }
            }

            if (groups.Count == 0)
            {
                hooks.Remove("PreToolUse");
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

    private bool HasHookEntry()
    {
        try
        {
            if (!File.Exists(HooksPath))
            {
                return false;
            }

            var root = JsonNode.Parse(File.ReadAllText(HooksPath)) as JsonObject;
            return root?["hooks"] is JsonObject hooks &&
                   hooks["PreToolUse"] is JsonArray groups &&
                   groups.OfType<JsonObject>().Any(group =>
                       group["hooks"] is JsonArray handlers &&
                       handlers.OfType<JsonObject>().Any(handler =>
                           handler["command"]?.ToString().Contains(Marker, StringComparison.Ordinal) == true));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    private bool MergeHookEntry()
    {
        JsonObject root;
        if (File.Exists(HooksPath))
        {
            root = JsonNode.Parse(File.ReadAllText(HooksPath)) as JsonObject ?? new JsonObject();
        }
        else
        {
            root = new JsonObject();
        }

        if (root["hooks"] is not JsonObject hooks)
        {
            hooks = new JsonObject();
            root["hooks"] = hooks;
        }

        if (hooks["PreToolUse"] is not JsonArray groups)
        {
            groups = new JsonArray();
            hooks["PreToolUse"] = groups;
        }

        if (HasHookEntry())
        {
            return true;
        }

        groups.Add(new JsonObject
        {
            ["matcher"] = ".*",
            ["hooks"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "command",
                    ["command"] = $"\"{PythonPath}\" \"{HookScriptPath}\"",
                    ["timeout"] = 10,
                },
            },
        });

        StorageSafety.BackupFile(HooksPath);
        File.WriteAllText(
            HooksPath,
            root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return true;
    }

    private static string BuildHookScript() => """
        # Managed by Netpetra. Calls the local Blackbox guard for Codex PreToolUse hooks.
        import contextlib
        import datetime
        import json
        import os
        import sys
        import time
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent
        sys.path.insert(0, str(ROOT))
        EVIDENCE = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Netpetra" / "agent-evidence.jsonl"


        def record(event_type, tool, decision, guard_status, duration_ms, error_code=""):
            try:
                EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
                if EVIDENCE.exists() and EVIDENCE.stat().st_size > 1_000_000:
                    lines = EVIDENCE.read_text(encoding="utf-8").splitlines()[-500:]
                    EVIDENCE.write_text("\n".join(lines) + "\n", encoding="utf-8")
                entry = {
                    "timestampUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "framework": "codex",
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
                with contextlib.redirect_stdout(sys.stderr):
                    from plugins.blackbox.guard.hooks import on_pre_tool_call

                    decision = on_pre_tool_call(
                        tool_name=tool,
                        args=payload.get("tool_input") or {},
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
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": decision.get("message") or "Blocked by Netpetra/Blackbox",
                        }
                    }))
                else:
                    print("{}")
            except Exception as exc:
                # Fail open: a Blackbox or hook fault must not break Codex.
                record("GUARD_FAILED", tool, "", "error",
                       int((time.monotonic() - started) * 1000), type(exc).__name__)
                print("{}")


        if __name__ == "__main__":
            main()
        """;
}
