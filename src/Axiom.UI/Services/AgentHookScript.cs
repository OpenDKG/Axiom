// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Blackbox;

namespace Axiom.UI.Services;

/// <summary>
/// One lifecycle bridge for Claude Code and Codex. Both hosts send JSON on stdin and differ only
/// in their blocking response shape; the Blackbox guard is shared. Hook faults remain fail-open.
/// </summary>
public static class AgentHookScript
{
    /// <summary>Bump when hook behavior changes so Codex invalidates its trust hash.</summary>
    public const string Version = "2";

    public static string Build(string framework) => ($$"""
        # Managed by Axiom. Calls the local Blackbox guard for Claude Code and Codex lifecycle hooks.
        import contextlib
        import datetime
        import json
        import os
        import re
        import sys
        import time
        from pathlib import Path

        FRAMEWORK = "{{framework}}"
        ROOT = Path(__file__).resolve().parent
        sys.path.insert(0, str(ROOT))
        EVIDENCE = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Axiom" / "agent-evidence.jsonl"
        PATCH_PATH = re.compile(r"^\*\*\*\s+(?:Update|Add|Delete)\s+File:\s*(.+?)\s*$", re.MULTILINE)


        # <<AXIOM_COMMAND_GUARD>>


        def record(event_type, tool="", decision="", guard_status="ok", duration_ms=0, error_code="",
                   session="", call=""):
            try:
                EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
                if EVIDENCE.exists() and EVIDENCE.stat().st_size > 1_000_000:
                    lines = EVIDENCE.read_text(encoding="utf-8").splitlines()[-500:]
                    EVIDENCE.write_text("\n".join(lines) + "\n", encoding="utf-8")
                entry = {
                    "timestampUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "framework": FRAMEWORK,
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


        def event_name(payload):
            return str(payload.get("hook_event_name") or payload.get("event") or "").strip().lower()


        def session_id(payload):
            for key in ("session_id", "conversation_id", "thread_id"):
                value = payload.get(key)
                if isinstance(value, (str, int)) and str(value).strip():
                    return str(value).strip()
            return ""


        def turn_id(payload):
            value = payload.get("turn_id") or payload.get("task_id")
            return str(value).strip() if value is not None else ""


        def workspace(payload):
            value = payload.get("cwd") or payload.get("workspace")
            return str(value).strip() if value is not None else ""


        def tool_call_id(payload):
            value = payload.get("tool_use_id") or payload.get("tool_call_id")
            return str(value).strip() if value is not None else ""


        def prompt(payload):
            for key in ("prompt", "user_prompt", "message", "input"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    return value
            return ""


        def tool_args(payload):
            raw = payload.get("tool_input")
            if raw is None:
                raw = payload.get("tool_args")
            if raw is None:
                raw = payload.get("input")
            if not isinstance(raw, dict):
                return raw
            args = dict(raw)
            tool = str(payload.get("tool_name") or "").strip().lower()
            if tool in ("apply_patch", "edit", "write") and not any(
                isinstance(args.get(key), str) and args.get(key)
                for key in ("path", "file", "file_path", "target")
            ):
                patch = args.get("command") or args.get("patch") or args.get("input")
                if isinstance(patch, str):
                    match = PATCH_PATH.search(patch)
                    if match:
                        args["path"] = match.group(1).strip()
            return args


        def deny(message):
            if FRAMEWORK == "codex":
                return {"decision": "block", "reason": message}
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": message,
                }
            }


        def audit_stop(sid, tid, ws):
            try:
                from plugins.blackbox import audit
                try:
                    audit.record(
                        event="stop",
                        detail={"session_id": sid, "turn_id": tid},
                        framework=FRAMEWORK,
                        workspace=ws or None,
                    )
                except TypeError:
                    audit.record(event="stop", detail={"session_id": sid, "turn_id": tid})
            except Exception:
                pass


        def main():
            started = time.monotonic()
            tool = ""
            sid = ""
            call = ""
            try:
                raw = sys.stdin.read()
                payload = json.loads(raw) if raw.strip() else {}
                if not isinstance(payload, dict):
                    return
                event = event_name(payload)
                sid = session_id(payload)
                tid = turn_id(payload)
                ws = workspace(payload)
                tool = str(payload.get("tool_name") or "")
                call = tool_call_id(payload)
                with contextlib.redirect_stdout(sys.stderr):
                    from plugins.blackbox.guard import hooks as guard

                if event in ("sessionstart", "session_start"):
                    if hasattr(guard, "on_session_start"):
                        guard.on_session_start(session_id=sid, framework=FRAMEWORK, workspace=ws)
                    record("SESSION_STARTED", "", "", "ok", int((time.monotonic() - started) * 1000),
                           session=sid)
                    return

                if event in ("userpromptsubmit", "user_prompt_submit"):
                    value = prompt(payload)
                    request_messages = [{"role": "user", "content": value}] if value else []
                    if hasattr(guard, "on_pre_api_request"):
                        guard.on_pre_api_request(
                            user_message=value,
                            request_messages=request_messages,
                            session_id=sid,
                            turn_id=tid,
                            model=payload.get("model"),
                            provider=FRAMEWORK,
                            framework=FRAMEWORK,
                            workspace=ws,
                        )
                    record("PROMPT_SCANNED", "", "", "ok", int((time.monotonic() - started) * 1000),
                           session=sid)
                    return

                if event in ("pretooluse", "pre_tool_use"):
                    parsed_args = tool_args(payload)
                    safety = _check_command_safety(parsed_args, _load_protected_paths())
                    if safety is not None:
                        record(
                            "GUARD_BLOCKED",
                            tool,
                            "block",
                            "blocked",
                            int((time.monotonic() - started) * 1000),
                            error_code=safety[0],
                            session=sid,
                            call=call,
                        )
                        sys.stdout.write(json.dumps(deny(safety[1]), separators=(",", ":")))
                        sys.stdout.flush()
                        return
                    decision = guard.on_pre_tool_call(
                        tool_name=tool,
                        args=parsed_args,
                        session_id=sid,
                        task_id=tid,
                        tool_call_id=tool_call_id(payload),
                        framework=FRAMEWORK,
                        workspace=ws,
                    )
                    blocked = bool(decision and decision.get("action") == "block")
                    record(
                        "GUARD_BLOCKED" if blocked else "GUARD_ALLOWED",
                        tool,
                        "block" if blocked else "allowed",
                        "blocked" if blocked else "allowed",
                        int((time.monotonic() - started) * 1000),
                        session=sid,
                        call=call,
                    )
                    if blocked:
                        message = str(decision.get("message") or "Blocked by Axiom/Blackbox")
                        sys.stdout.write(json.dumps(deny(message), separators=(",", ":")))
                        sys.stdout.flush()
                    return

                if event in ("posttooluse", "post_tool_use"):
                    result = payload.get("tool_response")
                    if result is None:
                        result = payload.get("tool_result")
                    if result is None:
                        result = payload.get("tool_output")
                    if hasattr(guard, "on_post_tool_call"):
                        guard.on_post_tool_call(
                            tool_name=tool,
                            args=tool_args(payload),
                            result=result,
                            session_id=sid,
                            task_id=tid,
                            tool_call_id=tool_call_id(payload),
                            framework=FRAMEWORK,
                            workspace=ws,
                        )
                    record("POST_TOOL", tool, "", "ok", int((time.monotonic() - started) * 1000),
                           session=sid, call=call)
                    return

                if event in ("stop", "turnend", "turn_end"):
                    audit_stop(sid, tid, ws)
                    record("STOPPED", tool, "", "ok", int((time.monotonic() - started) * 1000),
                           session=sid)
                    return

                if event in ("sessionend", "session_end"):
                    if hasattr(guard, "on_session_end"):
                        guard.on_session_end(
                            session_id=sid,
                            completed=True,
                            interrupted=False,
                            framework=FRAMEWORK,
                            workspace=ws,
                        )
                    record("SESSION_ENDED", "", "", "ok", int((time.monotonic() - started) * 1000),
                           session=sid)
                    return

                record("HOOK_EVENT", tool, "", "ignored", int((time.monotonic() - started) * 1000),
                       session=sid, call=call)
            except Exception as exc:
                # Fail open: a Blackbox or hook fault must not break the host agent.
                record(
                    "GUARD_FAILED",
                    tool,
                    "",
                    "error",
                    int((time.monotonic() - started) * 1000),
                    type(exc).__name__,
                    session=sid,
                    call=call,
                )


        if __name__ == "__main__":
            main()
        """).Replace("# <<AXIOM_COMMAND_GUARD>>", AgentCommandGuard.PythonHelpers, StringComparison.Ordinal);
}
