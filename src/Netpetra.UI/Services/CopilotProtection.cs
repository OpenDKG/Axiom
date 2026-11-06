// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Netpetra.UI.Services;

/// <summary>
/// Installs a Netpetra-owned Copilot CLI user hook file at
/// <c>~/.copilot/hooks/netpetra.json</c>. Copilot combines all user hook files; this adapter never
/// rewrites another hook file.
/// </summary>
public sealed class CopilotProtection
{
    private const string Marker = "netpetra-copilot-hook.py";
    private const string HookFileName = "netpetra.json";

    private readonly string _userProfile;

    private readonly string _localAppData;

    public CopilotProtection(string? userProfile = null, string? localAppData = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    public string ConfigDirectory => Path.Combine(_userProfile, ".copilot");

    public string HooksDirectory => Path.Combine(ConfigDirectory, "hooks");

    public string HooksPath => Path.Combine(HooksDirectory, HookFileName);

    private string BlackboxAgentRoot => Path.Combine(
        _localAppData,
        "Netpetra",
        "modules",
        "blackbox",
        "agent-blackbox");

    private string PythonPath => Path.Combine(BlackboxAgentRoot, "venv", "Scripts", "python.exe");

    public string HookScriptPath => Path.Combine(BlackboxAgentRoot, Marker);

    public bool IsCopilotDetected => Directory.Exists(ConfigDirectory) || AgentBinaryLocator.IsCopilotAvailable();

    public bool IsInstalled
    {
        get
        {
            try
            {
                return File.Exists(HookScriptPath) &&
                       File.Exists(HooksPath) &&
                       File.ReadAllText(HooksPath).Contains(Marker, StringComparison.Ordinal);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return false;
            }
        }
    }

    public bool EnsureInstalled()
    {
        if (!IsCopilotDetected || !File.Exists(PythonPath))
        {
            return false;
        }

        try
        {
            if (StorageSafety.IsReparsePointInPath(ConfigDirectory) ||
                StorageSafety.IsReparsePointInPath(HooksDirectory) ||
                StorageSafety.IsReparsePointInPath(HooksPath) ||
                StorageSafety.IsReparsePointInPath(HookScriptPath))
            {
                return false;
            }

            if (File.Exists(HooksPath) &&
                !File.ReadAllText(HooksPath).Contains("Managed by Netpetra", StringComparison.Ordinal))
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

            var hook = new JsonObject
            {
                ["description"] = "Managed by Netpetra. Local GitHub Copilot CLI guard hook.",
                ["version"] = 1,
                ["hooks"] = new JsonObject
                {
                    ["preToolUse"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["type"] = "command",
                            ["exec"] = PythonPath,
                            ["args"] = new JsonArray(JsonValue.Create(HookScriptPath)),
                            ["timeoutSec"] = 10,
                        },
                    },
                },
            };
            var content = hook.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
            if (!File.Exists(HooksPath) || File.ReadAllText(HooksPath) != content)
            {
                StorageSafety.BackupFile(HooksPath);
                Directory.CreateDirectory(HooksDirectory);
                File.WriteAllText(
                    HooksPath,
                    content,
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }

            return true;
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

            if (File.Exists(HooksPath) &&
                File.ReadAllText(HooksPath).Contains("Managed by Netpetra", StringComparison.Ordinal))
            {
                StorageSafety.BackupFile(HooksPath);
                File.Delete(HooksPath);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static string BuildHookScript() => """
        # Managed by Netpetra. Calls the local Blackbox guard for Copilot CLI preToolUse hooks.
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
                    "framework": "copilot",
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
                tool = str(payload.get("toolName") or payload.get("tool_name") or "")
                with contextlib.redirect_stdout(sys.stderr):
                    from plugins.blackbox.guard.hooks import on_pre_tool_call

                    decision = on_pre_tool_call(
                        tool_name=tool,
                        args=payload.get("toolArgs") or payload.get("tool_input") or {},
                        session_id=str(payload.get("sessionId") or payload.get("session_id") or ""),
                        tool_call_id=str(payload.get("toolCallId") or payload.get("tool_use_id") or ""),
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
                        "permissionDecision": "deny",
                        "permissionDecisionReason": decision.get("message") or "Blocked by Axiom/Blackbox",
                    }))
                else:
                    print(json.dumps({"permissionDecision": "allow"}))
            except Exception as exc:
                # Fail open by emitting an explicit allow; runtime failures never crash the CLI.
                record("GUARD_FAILED", tool, "", "error",
                       int((time.monotonic() - started) * 1000), type(exc).__name__)
                print(json.dumps({"permissionDecision": "allow"}))


        if __name__ == "__main__":
            main()
        """;
}
