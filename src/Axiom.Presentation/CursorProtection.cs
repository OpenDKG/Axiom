// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Axiom.Presentation;

/// <summary>
/// Installs a Cursor user-level <c>preToolUse</c> hook in <c>~/.cursor/hooks.json</c>. Existing
/// hooks and unrelated keys are preserved; project-level Cursor hooks are never touched.
/// </summary>
public sealed class CursorProtection
{
    private const string Marker = "axiom-cursor-hook.py";

    private readonly string _userProfile;

    private readonly string _localAppData;

    public CursorProtection(string? userProfile = null, string? localAppData = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    public string ConfigDirectory => Path.Combine(_userProfile, ".cursor");

    public string HooksPath => Path.Combine(ConfigDirectory, "hooks.json");

    private string BlackboxAgentRoot => Path.Combine(
        _localAppData,
        "Axiom",
        "modules",
        "blackbox",
        "agent-blackbox");

    private string PythonPath => Path.Combine(BlackboxAgentRoot, "venv", "Scripts", "python.exe");

    public string HookScriptPath => Path.Combine(BlackboxAgentRoot, Marker);

    private string ManagedCommand => $"\"{PythonPath}\" \"{HookScriptPath}\"";

    public bool IsCursorDetected => Directory.Exists(ConfigDirectory) || File.Exists(HooksPath) || AgentBinaryLocator.IsCursorAvailable();

    public bool IsInstalled => File.Exists(HookScriptPath) && HasHookEntry();

    public bool EnsureInstalled()
    {
        if (!IsCursorDetected || !File.Exists(PythonPath))
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
                StorageSafety.IsReparsePointInPath(HooksPath))
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
            if (root?["hooks"] is not JsonObject hooks ||
                hooks["preToolUse"] is not JsonArray handlers)
            {
                return;
            }

            var removed = false;
            for (var index = handlers.Count - 1; index >= 0; index--)
            {
                if (handlers[index] is JsonObject handler && IsOwnedHandler(handler))
                {
                    handlers.RemoveAt(index);
                    removed = true;
                }
            }

            if (!removed)
            {
                return;
            }

            if (handlers.Count == 0)
            {
                hooks.Remove("preToolUse");
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
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
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
                   hooks["preToolUse"] is JsonArray handlers &&
                   handlers.OfType<JsonObject>().Any(IsOwnedHandler);
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

        if (root["version"] is JsonNode version &&
            (version is not JsonValue value ||
             !value.TryGetValue<int>(out var versionNumber) ||
             versionNumber != 1))
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

        if (hooks["preToolUse"] is not null && hooks["preToolUse"] is not JsonArray)
        {
            return false;
        }

        if (hooks["preToolUse"] is not JsonArray handlers)
        {
            handlers = new JsonArray();
            hooks["preToolUse"] = handlers;
        }

        if (HasHookEntry())
        {
            return true;
        }

        root["version"] = 1;
        handlers.Add(new JsonObject
        {
            ["command"] = ManagedCommand,
            ["matcher"] = "*",
            ["timeout"] = 10,
        });

        StorageSafety.BackupFile(HooksPath);
        Directory.CreateDirectory(ConfigDirectory);
        File.WriteAllText(
            HooksPath,
            root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return true;
    }

    private static string BuildHookScript() => """
        # Managed by Axiom. Calls the local Blackbox guard for Cursor preToolUse hooks.
        import datetime
        import contextlib
        import json
        import os
        import sys
        import time
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent
        sys.path.insert(0, str(ROOT))
        EVIDENCE = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Axiom" / "agent-evidence.jsonl"


        def record(event_type, tool, decision, guard_status, duration_ms, error_code=""):
            try:
                EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
                if EVIDENCE.exists() and EVIDENCE.stat().st_size > 1_000_000:
                    lines = EVIDENCE.read_text(encoding="utf-8").splitlines()[-500:]
                    EVIDENCE.write_text("\n".join(lines) + "\n", encoding="utf-8")
                entry = {
                    "timestampUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "framework": "cursor",
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
                        session_id=str(payload.get("conversation_id", "")),
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
                    message = decision.get("message") or "Blocked by Axiom/Blackbox"
                    print(json.dumps({
                        "permission": "deny",
                        "user_message": message,
                        "agent_message": message,
                    }))
                else:
                    print(json.dumps({"permission": "allow"}))
            except Exception as exc:
                # Fail open: a Blackbox or hook fault must not break Cursor.
                record("GUARD_FAILED", tool, "", "error",
                       int((time.monotonic() - started) * 1000), type(exc).__name__)
                print(json.dumps({"permission": "allow"}))


        if __name__ == "__main__":
            main()
        """;
}
