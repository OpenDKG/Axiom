// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiom.Contracts.Blackbox;

namespace Axiom.UI.Services;

/// <summary>
/// Installs the Axiom guard as an Antigravity lifecycle hook. Antigravity reads global hooks from
/// <c>~/.gemini/config/hooks.json</c> and expects <c>{"decision":"allow|deny"}</c> on stdout, so a
/// small wrapper translates the shared Blackbox bridge result into that shape. The user file is
/// merged, never replaced.
/// </summary>
public sealed class AntigravityProtection
{
    private const string Marker = "axiom-antigravity-hook.py";

    private const string CmdWrapperMarker = "axiom-antigravity-hook.cmd";

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

    public string HookCmdPath => Path.Combine(BlackboxAgentRoot, CmdWrapperMarker);

    private bool RequiresCmdWrapper =>
        OperatingSystem.IsWindows() &&
        (NeedsCmdEscaping(PythonPath) || NeedsCmdEscaping(HookScriptPath));

    public bool IsAntigravityDetected =>
        Directory.Exists(Path.Combine(_userProfile, ".gemini")) ||
        File.Exists(HooksPath) ||
        File.Exists(Path.Combine(_localAppData, "Programs", "antigravity", "Antigravity.exe"));

    public bool IsInstalled =>
        File.Exists(PythonPath) &&
        File.Exists(HookScriptPath) &&
        (!RequiresCmdWrapper || File.Exists(HookCmdPath)) &&
        HasOwnedHook();

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
                StorageSafety.IsReparsePointInPath(HookScriptPath) ||
                StorageSafety.IsReparsePointInPath(HookCmdPath))
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

            if (RequiresCmdWrapper)
            {
                var wrapper = BuildCmdWrapper();
                if (!File.Exists(HookCmdPath) || File.ReadAllText(HookCmdPath) != wrapper)
                {
                    File.WriteAllText(
                        HookCmdPath,
                        wrapper,
                        new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                }
            }
            else if (File.Exists(HookCmdPath))
            {
                File.Delete(HookCmdPath);
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
                StorageSafety.IsReparsePointInPath(HookScriptPath) ||
                StorageSafety.IsReparsePointInPath(HookCmdPath))
            {
                return;
            }

            if (File.Exists(HookScriptPath))
            {
                File.Delete(HookScriptPath);
            }

            if (File.Exists(HookCmdPath))
            {
                File.Delete(HookCmdPath);
            }

            if (!File.Exists(HooksPath))
            {
                return;
            }

            var root = JsonNode.Parse(File.ReadAllText(HooksPath)) as JsonObject;
            if (root?.Remove(HookName) == true)
            {
                File.WriteAllText(
                    HooksPath,
                    root.ToJsonString(JsonOptions),
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
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

        // Antigravity invokes hooks on Windows via Go's exec.Command("cmd", "/c", command).
        // Go's syscall.EscapeArg escapes any embedded '"' as '\"', which cmd.exe rejects.
        // Never wrap paths in double quotes inside the command string; when paths contain
        // spaces or cmd metacharacters, invoke a local .cmd wrapper via caret escaping.
        var command = BuildHookCommand();
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

        File.WriteAllText(
            HooksPath,
            root.ToJsonString(JsonOptions),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return true;
    }

    private bool HasOwnedHook()
    {
        try
        {
            if (!File.Exists(HooksPath) || HasUtf8Bom(HooksPath))
            {
                return false;
            }

            var root = JsonNode.Parse(File.ReadAllText(HooksPath)) as JsonObject;
            if (root?[HookName]?["PreToolUse"] is not JsonArray groups)
            {
                return false;
            }

            var expectedCommand = BuildHookCommand();
            foreach (var group in groups)
            {
                if (group?["hooks"] is JsonArray handlers &&
                    handlers.Any(handler =>
                    {
                        var cmd = handler?["command"]?.GetValue<string>();
                        if (cmd is null || cmd.Contains('"', StringComparison.Ordinal))
                        {
                            return false;
                        }

                        if (RequiresCmdWrapper)
                        {
                            return string.Equals(cmd, expectedCommand, StringComparison.OrdinalIgnoreCase);
                        }

                        return cmd.Contains(Marker, StringComparison.OrdinalIgnoreCase);
                    }))
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

    private string BuildHookCommand() => RequiresCmdWrapper
        ? EscapeCmdPath(HookCmdPath)
        : $"{PythonPath} {HookScriptPath}";

    private static bool NeedsCmdEscaping(string path)
    {
        foreach (var ch in path)
        {
            if (char.IsWhiteSpace(ch) || ch is '&' or '(' or ')' or '^' or ',' or ';' or '=' or '[' or ']')
            {
                return true;
            }
        }

        return false;
    }

    private static string EscapeCmdPath(string path)
    {
        var sb = new StringBuilder(path.Length + 8);
        foreach (var ch in path)
        {
            if (ch is ' ' or '&' or '(' or ')' or '^' or ',' or ';' or '=' or '[' or ']')
            {
                sb.Append('^');
            }

            sb.Append(ch);
        }

        return sb.ToString();
    }

    private static string BuildCmdWrapper() =>
        "@echo off\r\n\"%~dp0venv\\Scripts\\python.exe\" \"%~dp0axiom-antigravity-hook.py\" %*\r\n";

    private static bool HasUtf8Bom(string path)
    {
        Span<byte> prefix = stackalloc byte[3];
        using var stream = File.OpenRead(path);
        return stream.Read(prefix) == 3 &&
               prefix[0] == 0xEF &&
               prefix[1] == 0xBB &&
               prefix[2] == 0xBF;
    }

    private static string BuildScript() => """
        # Managed by Axiom. Antigravity PreToolUse hook: asks the Blackbox guard and
        # translates its decision into Antigravity's {"decision": ...} shape.
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


        def record(event_type: str, tool: str, decision: str, guard_status: str, duration_ms: int,
                   error_code: str = "", session: str = "", call: str = "") -> None:
            try:
                EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
                if EVIDENCE.exists() and EVIDENCE.stat().st_size > 1_000_000:
                    lines = EVIDENCE.read_text(encoding="utf-8").splitlines()[-500:]
                    EVIDENCE.write_text("\n".join(lines) + "\n", encoding="utf-8")
                entry = {
                    "timestampUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "framework": "antigravity",
                    "eventType": event_type,
                    "tool": tool,
                    "decision": decision,
                    "guardStatus": guard_status,
                    "durationMs": duration_ms,
                    "errorCode": error_code,
                    "session": session,
                    "call": call,
                }
                with EVIDENCE.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry) + "\n")
            except Exception:
                pass


        def main() -> None:
            started = time.monotonic()
            tool = ""
            session = ""
            call = ""
            try:
                raw = sys.stdin.read()
                payload = json.loads(raw) if raw.strip() else {}
                if not isinstance(payload, dict):
                    print(json.dumps({"decision": "allow"}))
                    return
                tool_call = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
                tool = str(tool_call.get("name") or payload.get("tool_name") or "")
                args = tool_call.get("args") if "args" in tool_call else (payload.get("tool_input") or {})
                session = str(payload.get("conversationId") or payload.get("session_id") or "")
                step_idx = payload.get("stepIdx")
                call = str(step_idx if step_idx is not None else (payload.get("tool_use_id") or ""))
                workspaces = payload.get("workspacePaths")
                workspace = ",".join(str(p) for p in workspaces) if isinstance(workspaces, list) else str(payload.get("cwd") or "")
                parsed_args = args if isinstance(args, dict) else {}
                safety = _check_command_safety(parsed_args, _load_protected_paths())
                if safety is not None:
                    record(
                        "GUARD_BLOCKED",
                        tool,
                        "block",
                        "blocked",
                        int((time.monotonic() - started) * 1000),
                        error_code=safety[0],
                        session=session,
                        call=call,
                    )
                    print(json.dumps({"decision": "deny", "reason": safety[1]}))
                    return
                with contextlib.redirect_stdout(sys.stderr):
                    from plugins.blackbox.guard import hooks as guard
                    decision = guard.on_pre_tool_call(
                        tool_name=tool,
                        args=parsed_args,
                        session_id=session,
                        tool_call_id=call,
                        framework="antigravity",
                        workspace=workspace,
                    )
                blocked = bool(decision and str(decision.get("action") or "").lower() == "block")
                record(
                    "GUARD_BLOCKED" if blocked else "GUARD_ALLOWED",
                    tool,
                    "block" if blocked else "allowed",
                    "blocked" if blocked else "allowed",
                    int((time.monotonic() - started) * 1000),
                    session=session,
                    call=call,
                )
                if blocked:
                    reason = str(decision.get("message") or decision.get("reason") or "Blocked by the Axiom guard")
                    print(json.dumps({"decision": "deny", "reason": reason}))
                else:
                    print(json.dumps({"decision": "allow"}))
            except Exception as exc:
                # Fail open, like the other Axiom hooks: a guard fault must not break the host agent.
                record(
                    "GUARD_FAILED",
                    tool,
                    "",
                    "error",
                    int((time.monotonic() - started) * 1000),
                    type(exc).__name__,
                    session=session,
                    call=call,
                )
                print(json.dumps({"decision": "allow"}))


        if __name__ == "__main__":
            main()
        """.Replace("# <<AXIOM_COMMAND_GUARD>>", AgentCommandGuard.PythonHelpers, StringComparison.Ordinal);
}
