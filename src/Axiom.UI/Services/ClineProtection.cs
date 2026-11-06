// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;

namespace Axiom.UI.Services;

/// <summary>
/// Installs a user-level Cline PreToolUse hook at
/// <c>~/Documents/Cline/Hooks/PreToolUse.py</c>. Cline executes the hook file directly; Axiom
/// never overwrites a user-authored hook and never writes project-level .cline hooks.
/// </summary>
public sealed class ClineProtection
{
    private const string Marker = "Managed by Axiom";

    private readonly string _userProfile;

    private readonly string _localAppData;

    public ClineProtection(string? userProfile = null, string? localAppData = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    public string HooksDirectory => Path.Combine(_userProfile, "Documents", "Cline", "Hooks");

    public string HookPath => Path.Combine(HooksDirectory, "PreToolUse.py");

    private string BlackboxAgentRoot => Path.Combine(
        _localAppData,
        "Axiom",
        "modules",
        "blackbox",
        "agent-blackbox");

    private string PythonPath => Path.Combine(BlackboxAgentRoot, "venv", "Scripts", "python.exe");

    public bool IsClineDetected => Directory.Exists(Path.Combine(_userProfile, "Documents", "Cline")) || AgentBinaryLocator.IsClineAvailable();

    public bool IsInstalled
    {
        get
        {
            try
            {
                return File.Exists(HookPath) &&
                       File.ReadAllText(HookPath).Contains(Marker, StringComparison.Ordinal);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return false;
            }
        }
    }

    public bool EnsureInstalled()
    {
        if (!IsClineDetected || !File.Exists(PythonPath))
        {
            return false;
        }

        try
        {
            if (StorageSafety.IsReparsePointInPath(HooksDirectory) ||
                StorageSafety.IsReparsePointInPath(HookPath))
            {
                return false;
            }

            if (File.Exists(HookPath) && !IsManaged(File.ReadAllText(HookPath)))
            {
                return false;
            }

            var script = BuildHookScript();
            if (!File.Exists(HookPath) || File.ReadAllText(HookPath) != script)
            {
                StorageSafety.BackupFile(HookPath);
                Directory.CreateDirectory(HooksDirectory);
                File.WriteAllText(
                    HookPath,
                    script,
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }

            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public void Remove()
    {
        try
        {
            if (!File.Exists(HookPath) ||
                StorageSafety.IsReparsePointInPath(HookPath) ||
                !IsManaged(File.ReadAllText(HookPath)))
            {
                return;
            }

            StorageSafety.BackupFile(HookPath);
            File.Delete(HookPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static bool IsManaged(string text) =>
        text.Contains(Marker, StringComparison.Ordinal) ||
        LegacyHookIdentity.IsLegacyManagedText(text);

    private string BuildHookScript() => $$"""
        # Managed by Axiom. Calls the local Blackbox guard for Cline PreToolUse.
        import datetime
        import contextlib
        import json
        import os
        import sys
        import time
        from pathlib import Path

        ROOT = Path(r"{{BlackboxAgentRoot}}")
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
                    "framework": "cline",
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
                call = payload.get("tool_call") or {}
                tool = str(call.get("name", ""))
                with contextlib.redirect_stdout(sys.stderr):
                    from plugins.blackbox.guard.hooks import on_pre_tool_call

                    decision = on_pre_tool_call(
                        tool_name=tool,
                        args=call.get("input") or {},
                        session_id=str(payload.get("taskId", "")),
                        tool_call_id=str(call.get("id", "")),
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
                        "cancel": True,
                        "errorMessage": decision.get("message") or "Blocked by Axiom/Blackbox",
                    }))
                else:
                    print(json.dumps({}))
            except Exception as exc:
                # Fail open: a Blackbox or hook fault must not break Cline.
                record("GUARD_FAILED", tool, "", "error",
                       int((time.monotonic() - started) * 1000), type(exc).__name__)
                print(json.dumps({}))


        if __name__ == "__main__":
            main()
        """;
}
