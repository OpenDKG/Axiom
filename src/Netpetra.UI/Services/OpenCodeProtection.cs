// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;

namespace Netpetra.UI.Services;

/// <summary>
/// Installs the Netpetra/Blackbox guard plugin for OpenCode. OpenChamber uses the same
/// <c>~/.config/opencode</c> plugin directory, so one plugin covers both. The plugin calls the
/// Blackbox Python guard for every tool call; bridge failures fail open, matching Hermes.
/// </summary>
public sealed class OpenCodeProtection
{
    private readonly string _userProfile;

    private readonly string _localAppData;

    private readonly string _roamingAppData;

    public OpenCodeProtection(
        string? userProfile = null,
        string? localAppData = null,
        string? roamingAppData = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _roamingAppData = roamingAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    }

    public string ConfigDirectory => Path.Combine(_userProfile, ".config", "opencode");

    /// <summary>OpenCode V2 directory plugin; this is the entrypoint V2 loads.</summary>
    public string PluginDirectory => Path.Combine(ConfigDirectory, "plugins", "netpetra-blackbox");

    /// <summary>OpenCode V2 entrypoint. V2 requires a directory package with index.ts.</summary>
    public string PluginPath => Path.Combine(PluginDirectory, "index.ts");

    /// <summary>OpenCode V1 flat-file fallback. Its setup is a no-op under V2.</summary>
    public string V1PluginPath => Path.Combine(ConfigDirectory, "plugins", "netpetra-blackbox.ts");

    /// <summary>Older V1 singular plugin file, removed only when Netpetra-owned.</summary>
    public string LegacyPluginPath => Path.Combine(ConfigDirectory, "plugin", "netpetra-blackbox.ts");

    public string OpenChamberPath => Path.Combine(
        _localAppData,
        "Programs",
        "@openchamberelectron",
        "OpenChamber.exe");

    private string BlackboxAgentRoot => Path.Combine(
        _localAppData,
        "Netpetra",
        "modules",
        "blackbox",
        "agent-blackbox");

    private string PythonPath => Path.Combine(BlackboxAgentRoot, "venv", "Scripts", "python.exe");

    public string BridgePath => Path.Combine(BlackboxAgentRoot, "netpetra-guard-bridge.py");

    public string EvidencePath => Path.Combine(_localAppData, "Netpetra", "agent-evidence.jsonl");

    public bool IsOpenCodeDetected => Directory.Exists(ConfigDirectory);

    public bool IsOpenChamberDetected =>
        File.Exists(OpenChamberPath) ||
        Directory.Exists(Path.Combine(_roamingAppData, "openchamber"));

    public bool IsInstalled
    {
        get
        {
            try
            {
                if (!File.Exists(PluginPath) || !File.Exists(BridgePath))
                {
                    return false;
                }

                var source = File.ReadAllText(PluginPath);
                return source.Contains("Managed by Netpetra", StringComparison.Ordinal) &&
                       source.Contains("Plugin.define", StringComparison.Ordinal) &&
                       source.Contains("ctx.tool.hook", StringComparison.Ordinal);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return false;
            }
        }
    }

    /// <summary>Writes the bridge, V2 directory plugin and V1 fallback when OpenCode and the Blackbox venv are present.</summary>
    public bool EnsureInstalled()
    {
        if (!IsOpenCodeDetected || !File.Exists(PythonPath))
        {
            return false;
        }

        try
        {
            if (StorageSafety.IsReparsePointInPath(ConfigDirectory) ||
                StorageSafety.IsReparsePointInPath(PluginDirectory) ||
                StorageSafety.IsReparsePointInPath(PluginPath) ||
                StorageSafety.IsReparsePointInPath(V1PluginPath) ||
                StorageSafety.IsReparsePointInPath(LegacyPluginPath) ||
                StorageSafety.IsReparsePointInPath(BridgePath))
            {
                // Never write through a junction/symlink in a user-managed agent configuration.
                return false;
            }

            Directory.CreateDirectory(PluginDirectory);

            if (File.Exists(PluginPath) && !IsManaged(PluginPath))
            {
                // Never overwrite a user-authored V2 plugin at the Netpetra path.
                return false;
            }

            if (File.Exists(LegacyPluginPath) && IsManaged(LegacyPluginPath))
            {
                StorageSafety.BackupFile(LegacyPluginPath);
                File.Delete(LegacyPluginPath);
            }

            var bridge = BuildBridge();
            if (!File.Exists(BridgePath) || File.ReadAllText(BridgePath) != bridge)
            {
                File.WriteAllText(BridgePath, bridge, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }

            WriteManagedFile(PluginPath, BuildV2Plugin());

            try
            {
                if (!File.Exists(V1PluginPath) || IsManaged(V1PluginPath))
                {
                    WriteManagedFile(V1PluginPath, BuildV1Plugin());
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // The V2 directory plugin is already installed; a blocked V1 fallback is not fatal.
            }

            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool IsManaged(string path) =>
        File.ReadAllText(path).Contains("Managed by Netpetra", StringComparison.Ordinal);

    private static void WriteManagedFile(string path, string content)
    {
        if (File.Exists(path) && File.ReadAllText(path) == content)
        {
            return;
        }

        StorageSafety.BackupFile(path);
        File.WriteAllText(path, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private string BuildV1Plugin()
    {
        var python = JsPath(PythonPath);
        var bridge = JsPath(BridgePath);
        var workingDirectory = JsPath(BlackboxAgentRoot);
        var evidence = JsPath(EvidencePath);

        return $$"""
            // Managed by Netpetra. OpenCode V1 fallback; V2 is handled by the directory plugin.
            import { spawnSync } from "node:child_process"
            import { appendFileSync } from "node:fs"

            const python = "{{python}}"
            const bridge = "{{bridge}}"
            const workingDirectory = "{{workingDirectory}}"
            const evidence = "{{evidence}}"

            function record(eventType, tool, decision, guardStatus, durationMs, errorCode) {
              try {
                appendFileSync(evidence, JSON.stringify({
                  timestampUtc: new Date().toISOString(),
                  framework: "opencode",
                  eventType,
                  tool: tool || "",
                  decision: decision || "",
                  guardStatus: guardStatus || "",
                  durationMs: durationMs || 0,
                  errorCode: errorCode || "",
                }) + "\n")
              } catch {
              }
            }

            export default {
              id: "netpetra-blackbox-v1",
              async setup(context) {
                // V2 loads the directory plugin and passes ctx.app.version. Do not register twice.
                if (context?.app?.version?.startsWith("2.")) return
                record("HOOK_LOADED", "", "", "loaded", 0, "")
                context.tool.hook("execute.before", async (event) => {
                  const started = Date.now()
                  let decision
                  try {
                    const result = spawnSync(python, [bridge], {
                      input: JSON.stringify({
                        framework: "opencode",
                        tool: event.tool,
                        args: event.input,
                        session: event.sessionID,
                        call: event.id,
                      }),
                      cwd: workingDirectory,
                      encoding: "utf8",
                      timeout: 8000,
                      windowsHide: true,
                    })
                    if (result.status !== 0 || !result.stdout) {
                      record("GUARD_FAILED", event.tool, "", "error", Date.now() - started, "bridge")
                      return
                    }
                    decision = JSON.parse(result.stdout)
                  } catch {
                    record("GUARD_FAILED", event.tool, "", "error", Date.now() - started, "spawn")
                    return
                  }

                  const blocked = decision && decision.action === "block"
                  record(
                    blocked ? "GUARD_BLOCKED" : "GUARD_ALLOWED",
                    event.tool,
                    blocked ? "block" : "allowed",
                    blocked ? "blocked" : "allowed",
                    Date.now() - started,
                    "")
                  if (blocked) {
                    throw new Error(decision.message || "Blocked by Axiom/Blackbox")
                  }
                })
              },
            }
            """;
    }

    private string BuildV2Plugin()
    {
        var python = JsPath(PythonPath);
        var bridge = JsPath(BridgePath);
        var workingDirectory = JsPath(BlackboxAgentRoot);
        var evidence = JsPath(EvidencePath);

        return $$"""
            // Managed by Netpetra. OpenCode V2 directory plugin.
            import { Plugin } from "@opencode/plugin"
            import { spawnSync } from "node:child_process"
            import { appendFileSync } from "node:fs"

            const python = "{{python}}"
            const bridge = "{{bridge}}"
            const workingDirectory = "{{workingDirectory}}"
            const evidence = "{{evidence}}"

            function record(eventType, tool, decision, guardStatus, durationMs, errorCode) {
              try {
                appendFileSync(evidence, JSON.stringify({
                  timestampUtc: new Date().toISOString(),
                  framework: "opencode",
                  eventType,
                  tool: tool || "",
                  decision: decision || "",
                  guardStatus: guardStatus || "",
                  durationMs: durationMs || 0,
                  errorCode: errorCode || "",
                }) + "\n")
              } catch {
              }
            }

            export default Plugin.define({
              id: "netpetra-blackbox-v2",
              async setup(ctx) {
                record("HOOK_LOADED", "", "", "loaded", 0, "")
                await ctx.tool.hook("execute.before", async (event) => {
                  const started = Date.now()
                  let decision
                  try {
                    const result = spawnSync(python, [bridge], {
                      input: JSON.stringify({
                        framework: "opencode",
                        tool: event.tool,
                        args: event.input,
                        session: event.sessionID,
                        call: event.id,
                      }),
                      cwd: workingDirectory,
                      encoding: "utf8",
                      timeout: 8000,
                      windowsHide: true,
                    })
                    if (result.status !== 0 || !result.stdout) {
                      record("GUARD_FAILED", event.tool, "", "error", Date.now() - started, "bridge")
                      return
                    }
                    decision = JSON.parse(result.stdout)
                  } catch {
                    record("GUARD_FAILED", event.tool, "", "error", Date.now() - started, "spawn")
                    return
                  }

                  const blocked = decision && decision.action === "block"
                  record(
                    blocked ? "GUARD_BLOCKED" : "GUARD_ALLOWED",
                    event.tool,
                    blocked ? "block" : "allowed",
                    blocked ? "blocked" : "allowed",
                    Date.now() - started,
                    "")
                  if (blocked) {
                    throw new Error(decision.message || "Blocked by Axiom/Blackbox")
                  }
                })
              },
            })
            """;
    }

    private static string BuildBridge() => """
        # Managed by Netpetra. Calls the local Blackbox guard for OpenCode/OpenChamber tool calls.
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


        def record(framework, event_type, tool, decision, guard_status, duration_ms, error_code=""):
            try:
                EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
                if EVIDENCE.exists() and EVIDENCE.stat().st_size > 1_000_000:
                    lines = EVIDENCE.read_text(encoding="utf-8").splitlines()[-500:]
                    EVIDENCE.write_text("\n".join(lines) + "\n", encoding="utf-8")
                entry = {
                    "timestampUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "framework": framework,
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
            payload = {}
            started = time.monotonic()
            framework = "opencode"
            tool = ""
            try:
                payload = json.load(sys.stdin)
                framework = str(payload.get("framework") or "opencode")
                tool = str(payload.get("tool", ""))
                with contextlib.redirect_stdout(sys.stderr):
                    from plugins.blackbox.guard.hooks import on_pre_tool_call

                    decision = on_pre_tool_call(
                        tool_name=tool,
                        args=payload.get("args") or {},
                        session_id=str(payload.get("session", "")),
                        tool_call_id=str(payload.get("call", "")),
                    )
                blocked = bool(decision and decision.get("action") == "block")
                record(
                    framework,
                    "GUARD_BLOCKED" if blocked else "GUARD_ALLOWED",
                    tool,
                    "block" if blocked else "allowed",
                    "blocked" if blocked else "allowed",
                    int((time.monotonic() - started) * 1000))
                print(json.dumps(decision or {}))
            except Exception as exc:
                # Fail open: a Blackbox or bridge fault must not break the host agent.
                record(framework, "GUARD_FAILED", tool, "", "error",
                       int((time.monotonic() - started) * 1000), type(exc).__name__)
                print("{}")


        if __name__ == "__main__":
            main()
        """;

    private static string JsPath(string path) =>
        path.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);
}
