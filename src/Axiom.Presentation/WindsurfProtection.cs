// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiom.Contracts.Blackbox;

namespace Axiom.Presentation;

/// <summary>
/// Installs user-level Windsurf Cascade pre-hooks in ~/.codeium/windsurf/hooks.json. Only the three
/// blocking pre-hook events are registered; unrelated hooks and settings are preserved.
/// </summary>
public sealed class WindsurfProtection
{
    private const string Marker = "axiom-windsurf-hook.py";

    private static readonly string[] Events =
    [
        "pre_run_command",
        "pre_write_code",
        "pre_mcp_tool_use",
    ];

    private readonly string _userProfile;

    private readonly string _localAppData;

    public WindsurfProtection(string? userProfile = null, string? localAppData = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    public string ConfigDirectory => Path.Combine(_userProfile, ".codeium", "windsurf");

    public string HooksPath => Path.Combine(ConfigDirectory, "hooks.json");

    private string BlackboxAgentRoot => Path.Combine(
        _localAppData,
        "Axiom",
        "modules",
        "blackbox",
        "agent-blackbox");

    private string PythonPath => AgentPlatform.VenvPython(BlackboxAgentRoot);

    public string HookScriptPath => Path.Combine(BlackboxAgentRoot, Marker);

    // Windows Cascade hooks run through PowerShell ("powershell" key); macOS/Linux hooks run
    // through the POSIX shell ("command" key).
    private static string CommandKey => OperatingSystem.IsWindows() ? "powershell" : "command";

    private string ManagedCommand => OperatingSystem.IsWindows()
        ? $"& \"{PythonPath}\" \"{HookScriptPath}\""
        : $"\"{PythonPath}\" \"{HookScriptPath}\"";

    public bool IsWindsurfDetected => Directory.Exists(ConfigDirectory) || File.Exists(HooksPath) || AgentBinaryLocator.IsWindsurfAvailable();

    public bool IsInstalled => File.Exists(HookScriptPath) && HasHookEntry();

    public bool EnsureInstalled()
    {
        if (!IsWindsurfDetected || !File.Exists(PythonPath))
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
            if (root?["hooks"] is not JsonObject hooks)
            {
                return;
            }

            var removed = false;
            foreach (var eventName in Events)
            {
                if (hooks[eventName] is not JsonArray handlers)
                {
                    continue;
                }

                for (var index = handlers.Count - 1; index >= 0; index--)
                {
                    if (handlers[index] is JsonObject handler && IsOwnedHandler(handler))
                    {
                        handlers.RemoveAt(index);
                        removed = true;
                    }
                }

                if (handlers.Count == 0)
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
            if (root?["hooks"] is not JsonObject hooks)
            {
                return false;
            }

            foreach (var eventName in Events)
            {
                if (hooks[eventName] is JsonArray handlers &&
                    handlers.OfType<JsonObject>().Any(IsOwnedHandler))
                {
                    return true;
                }
            }

            return false;
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    private bool IsOwnedHandler(JsonObject handler) =>
        handler[CommandKey] is JsonValue value &&
        value.TryGetValue<string>(out var command) &&
        (string.Equals(command, ManagedCommand, StringComparison.OrdinalIgnoreCase) ||
         LegacyHookIdentity.IsLegacyCommand(command));

    private bool MergeHookEntries()
    {
        var root = File.Exists(HooksPath)
            ? JsonNode.Parse(File.ReadAllText(HooksPath)) as JsonObject
            : new JsonObject();
        if (root is null)
        {
            return false;
        }

        if (root["hooks"] is not JsonObject hooks)
        {
            if (root["hooks"] is not null)
            {
                return false;
            }

            hooks = new JsonObject();
            root["hooks"] = hooks;
        }

        foreach (var eventName in Events)
        {
            if (hooks[eventName] is not JsonArray handlers)
            {
                if (hooks[eventName] is not null)
                {
                    return false;
                }

                handlers = new JsonArray();
                hooks[eventName] = handlers;
            }

            if (handlers.OfType<JsonObject>().Any(IsOwnedHandler))
            {
                continue;
            }

            handlers.Add(new JsonObject
            {
                [CommandKey] = ManagedCommand,
                ["show_output"] = false,
            });
        }

        StorageSafety.BackupFile(HooksPath);
        Directory.CreateDirectory(ConfigDirectory);
        File.WriteAllText(
            HooksPath,
            root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return true;
    }

    private static string BuildHookScript() => AgentPlatform.AdaptHookScript("""
        # Managed by Axiom. Calls the local Blackbox guard for Windsurf Cascade pre-hooks.
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


        # <<AXIOM_COMMAND_GUARD>>


        def record(event_type, tool, decision, guard_status, duration_ms, error_code=""):
            try:
                EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
                if EVIDENCE.exists() and EVIDENCE.stat().st_size > 1_000_000:
                    lines = EVIDENCE.read_text(encoding="utf-8").splitlines()[-500:]
                    EVIDENCE.write_text("\n".join(lines) + "\n", encoding="utf-8")
                entry = {
                    "timestampUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "framework": "windsurf",
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
                action = str(payload.get("agent_action_name", ""))
                info = payload.get("tool_info") or {}
                if action == "pre_run_command":
                    tool = "run_command"
                    args = {"command": info.get("command_line", ""), "cwd": info.get("cwd", "")}
                elif action == "pre_write_code":
                    tool = "write_code"
                    args = {"file_path": info.get("file_path", ""), "edits": info.get("edits", [])}
                elif action == "pre_mcp_tool_use":
                    tool = str(info.get("tool_name") or info.get("name") or "mcp_tool")
                    args = info.get("tool_input") or info.get("args") or info
                else:
                    tool = action or "unknown"
                    args = info

                safety = _check_command_safety(args, _load_protected_paths())
                if safety is not None:
                    record(
                        "GUARD_BLOCKED",
                        tool,
                        "block",
                        "blocked",
                        int((time.monotonic() - started) * 1000),
                        error_code=safety[0])
                    print(safety[1], file=sys.stderr)
                    sys.exit(2)

                with contextlib.redirect_stdout(sys.stderr):
                    from plugins.blackbox.guard.hooks import on_pre_tool_call

                    decision = on_pre_tool_call(
                        tool_name=tool,
                        args=args,
                        session_id=str(payload.get("trajectory_id") or payload.get("session_id") or ""),
                        tool_call_id=str(payload.get("execution_id") or ""),
                    )
                blocked = bool(decision and decision.get("action") == "block")
                record(
                    "GUARD_BLOCKED" if blocked else "GUARD_ALLOWED",
                    tool,
                    "block" if blocked else "allowed",
                    "blocked" if blocked else "allowed",
                    int((time.monotonic() - started) * 1000))
                if blocked:
                    print(decision.get("message") or "Blocked by Axiom/Blackbox", file=sys.stderr)
                    sys.exit(2)
            except Exception as exc:
                duration_ms = int((time.monotonic() - started) * 1000)
                if _is_fail_closed():
                    record("GUARD_FAILED", tool, "block", "failed_closed", duration_ms, type(exc).__name__)
                    print("Blocked by Axiom (Fail-closed strict mode): Blackbox guard is unavailable or failed to verify this tool call.", file=sys.stderr)
                    sys.exit(2)
                # Fail open: a Blackbox or hook fault must not break Windsurf.
                record("GUARD_FAILED", tool, "", "error", duration_ms, type(exc).__name__)


        if __name__ == "__main__":
            main()
        """.Replace("# <<AXIOM_COMMAND_GUARD>>", AgentCommandGuard.PythonHelpers, StringComparison.Ordinal));
}
