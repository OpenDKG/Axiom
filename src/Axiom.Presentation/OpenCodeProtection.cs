// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;

namespace Axiom.Presentation;

/// <summary>
/// Installs the Axiom/Blackbox guard plugin for OpenCode. OpenChamber uses the same
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
    public string PluginDirectory => Path.Combine(ConfigDirectory, "plugins", "axiom-blackbox");

    /// <summary>OpenCode V2 entrypoint. V2 requires a directory package with index.ts.</summary>
    public string PluginPath => Path.Combine(PluginDirectory, "index.ts");

    /// <summary>OpenCode V1 flat-file fallback. Its setup is a no-op under V2.</summary>
    public string V1PluginPath => Path.Combine(ConfigDirectory, "plugins", "axiom-blackbox.ts");

    /// <summary>Older V1 singular plugin file, removed only when Axiom-owned.</summary>
    public string LegacyPluginPath => Path.Combine(ConfigDirectory, "plugin", "axiom-blackbox.ts");

    public string PreRenamePluginDirectory =>
        Path.Combine(ConfigDirectory, "plugins", Axiom.Contracts.LegacyIdentity.OpenCodePluginName);

    public string PreRenameV1PluginPath =>
        Path.Combine(ConfigDirectory, "plugins", Axiom.Contracts.LegacyIdentity.OpenCodeV1PluginFileName);

    public string PreRenameSingularPluginPath =>
        Path.Combine(ConfigDirectory, "plugin", Axiom.Contracts.LegacyIdentity.OpenCodeV1PluginFileName);

    public string PreRenameBridgePath =>
        Path.Combine(BlackboxAgentRoot, Axiom.Contracts.LegacyIdentity.GuardBridgeFileName);

    public string OpenChamberPath => Path.Combine(
        _localAppData,
        "Programs",
        "@openchamberelectron",
        "OpenChamber.exe");

    private string BlackboxAgentRoot => Path.Combine(
        _localAppData,
        "Axiom",
        "modules",
        "blackbox",
        "agent-blackbox");

    private string PythonPath => Path.Combine(BlackboxAgentRoot, "venv", "Scripts", "python.exe");

    public string BridgePath => Path.Combine(BlackboxAgentRoot, "axiom-guard-bridge.py");

    public string EvidencePath => Path.Combine(_localAppData, "Axiom", "agent-evidence.jsonl");

    public bool IsOpenCodeDetected => Directory.Exists(ConfigDirectory) || AgentBinaryLocator.IsOpenCodeAvailable();

    public bool IsOpenChamberDetected =>
        File.Exists(OpenChamberPath) ||
        Directory.Exists(Path.Combine(_roamingAppData, "openchamber")) ||
        AgentBinaryLocator.IsOpenChamberAvailable();

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
                return source.Contains("Managed by Axiom", StringComparison.Ordinal) &&
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

            RemovePreRenameManagedFiles();
            Directory.CreateDirectory(PluginDirectory);

            if (File.Exists(PluginPath) && !IsManaged(PluginPath))
            {
                // Never overwrite a user-authored V2 plugin at the Axiom path.
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
        File.ReadAllText(path).Contains("Managed by Axiom", StringComparison.Ordinal);

    private static void WriteManagedFile(string path, string content)
    {
        if (File.Exists(path) && File.ReadAllText(path) == content)
        {
            return;
        }

        StorageSafety.BackupFile(path);
        File.WriteAllText(path, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private void RemovePreRenameManagedFiles()
    {
        try
        {
            if (Directory.Exists(PreRenamePluginDirectory) &&
                Directory.EnumerateFiles(PreRenamePluginDirectory, "*", SearchOption.AllDirectories)
                    .Any(file => LegacyHookIdentity.IsLegacyManagedText(SafeRead(file))))
            {
                Directory.Delete(PreRenamePluginDirectory, recursive: true);
            }

            foreach (var path in new[] { PreRenameV1PluginPath, PreRenameSingularPluginPath, PreRenameBridgePath })
            {
                if (File.Exists(path) && LegacyHookIdentity.IsLegacyManagedText(SafeRead(path)))
                {
                    File.Delete(path);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static string? SafeRead(string path)
    {
        try
        {
            return File.ReadAllText(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private string BuildV1Plugin()
    {
        var python = JsPath(PythonPath);
        var bridge = JsPath(BridgePath);
        var workingDirectory = JsPath(BlackboxAgentRoot);
        var evidence = JsPath(EvidencePath);

        return $$"""
            // Managed by Axiom. OpenCode V1 fallback; V2 is handled by the directory plugin.
            import { spawn, spawnSync } from "node:child_process"
            import { appendFileSync } from "node:fs"

            const python = "{{python}}"
            const bridge = "{{bridge}}"
            const workingDirectory = "{{workingDirectory}}"
            const evidence = "{{evidence}}"

            function record(eventType, tool, decision, guardStatus, durationMs, errorCode, session, call) {
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
                  session: session || "",
                  call: call || "",
                }) + "\n")
              } catch {
              }
            }

            {{BuildLifecycleScript()}}

            export default {
              id: "axiom-blackbox-v1",
              async setup(context) {
                // V2 loads the directory plugin and passes ctx.app.version. Do not register twice.
                if (context?.app?.version?.startsWith("2.")) return
                if (globalThis.__axiomBlackboxHooksInstalled) return
                globalThis.__axiomBlackboxHooksInstalled = true
                record("HOOK_LOADED", "", "", "loaded", 0, "")
                startLifecycle()
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
                      record("GUARD_FAILED", event.tool, "", "error", Date.now() - started, "bridge", event.sessionID, event.id)
                      return
                    }
                    decision = JSON.parse(result.stdout)
                  } catch {
                    record("GUARD_FAILED", event.tool, "", "error", Date.now() - started, "spawn", event.sessionID, event.id)
                    return
                  }

                  const blocked = decision && decision.action === "block"
                  record(
                    blocked ? "GUARD_BLOCKED" : "GUARD_ALLOWED",
                    event.tool,
                    blocked ? "block" : "allowed",
                    blocked ? "blocked" : "allowed",
                    Date.now() - started,
                    "",
                    event.sessionID,
                    event.id)
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
            // Managed by Axiom. OpenCode V2 directory plugin.
            import { Plugin } from "@opencode/plugin"
            import { spawn, spawnSync } from "node:child_process"
            import { appendFileSync } from "node:fs"

            const python = "{{python}}"
            const bridge = "{{bridge}}"
            const workingDirectory = "{{workingDirectory}}"
            const evidence = "{{evidence}}"

            function record(eventType, tool, decision, guardStatus, durationMs, errorCode, session, call) {
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
                  session: session || "",
                  call: call || "",
                }) + "\n")
              } catch {
              }
            }

            {{BuildLifecycleScript()}}

            export default Plugin.define({
              id: "axiom-blackbox-v2",
              async setup(ctx) {
                if (globalThis.__axiomBlackboxHooksInstalled) return
                globalThis.__axiomBlackboxHooksInstalled = true
                record("HOOK_LOADED", "", "", "loaded", 0, "")
                startLifecycle()
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
                      record("GUARD_FAILED", event.tool, "", "error", Date.now() - started, "bridge", event.sessionID, event.id)
                      return
                    }
                    decision = JSON.parse(result.stdout)
                  } catch {
                    record("GUARD_FAILED", event.tool, "", "error", Date.now() - started, "spawn", event.sessionID, event.id)
                    return
                  }

                  const blocked = decision && decision.action === "block"
                  record(
                    blocked ? "GUARD_BLOCKED" : "GUARD_ALLOWED",
                    event.tool,
                    blocked ? "block" : "allowed",
                    blocked ? "blocked" : "allowed",
                    Date.now() - started,
                    "",
                    event.sessionID,
                    event.id)
                  if (blocked) {
                    throw new Error(decision.message || "Blocked by Axiom/Blackbox")
                  }
                })
              },
            })
            """;
    }

    private static string BuildLifecycleScript() => """
        function runLifecycleBridge(payload) {
          try {
            const child = spawn(python, [bridge], {
              cwd: workingDirectory,
              windowsHide: true,
              stdio: ["pipe", "ignore", "ignore"],
            })
            child.stdin.write(JSON.stringify(payload))
            child.stdin.end()
          } catch {
          }
        }

        function startLifecycle() {
          if (globalThis.__axiomLifecycleStarted) return
          globalThis.__axiomLifecycleStarted = true

          const portIndex = process.argv.indexOf("--port")
          const port = portIndex >= 0
            ? process.argv[portIndex + 1]
            : (process.env.OPENCODE_PORT || process.env.OPENCODE_SERVER_PORT)
          if (!port) return

          const password = process.env.OPENCODE_SERVER_PASSWORD || process.env.OPENCODE_PASSWORD || ""
          const headers = password
            ? { Authorization: "Basic " + Buffer.from("opencode:" + password).toString("base64") }
            : {}
          const seen = new Set()

          const handle = (event) => {
            const type = event?.type || ""
            const data = event?.data || event?.properties || {}
            const session = data.sessionID || data.info?.id || data.session?.id || ""
            if (!session) return

            if (!seen.has(session) &&
                (type === "session.created" ||
                 type === "session.step.started" ||
                 type === "session.tool.called" ||
                 type === "message.updated")) {
              seen.add(session)
              runLifecycleBridge({
                framework: "opencode",
                event: "session_start",
                session,
                workspace: data.info?.directory || "",
              })
            }

            if (type === "session.step.started") {
              runLifecycleBridge({
                framework: "opencode",
                event: "pre_api_request",
                session,
                model: data.model,
                workspace: data.info?.directory || "",
              })
            }

            if (type === "session.deleted") {
              seen.delete(session)
              runLifecycleBridge({
                framework: "opencode",
                event: "session_end",
                session,
              })
            }
          }

          const connect = async () => {
            try {
              const response = await fetch(`http://127.0.0.1:${port}/api/event`, { headers })
              if (!response.ok || !response.body) throw new Error("event stream unavailable")
              const reader = response.body.getReader()
              const decoder = new TextDecoder()
              let buffer = ""
              while (true) {
                const { done, value } = await reader.read()
                if (done) break
                buffer += decoder.decode(value, { stream: true })
                let index
                while ((index = buffer.indexOf("\n\n")) >= 0) {
                  const block = buffer.slice(0, index)
                  buffer = buffer.slice(index + 2)
                  const line = block.split(/\r?\n/).find((item) => item.startsWith("data:"))
                  if (!line) continue
                  try {
                    handle(JSON.parse(line.slice(5).trim()))
                  } catch {
                  }
                }
              }
            } catch {
            }
            setTimeout(connect, 2000)
          }

          connect()
        }
        """;

    private static string BuildBridge() => """
        # Managed by Axiom. Calls the local Blackbox guard for OpenCode/OpenChamber tool calls.
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


        def record(framework, event_type, tool, decision, guard_status, duration_ms,
                   error_code="", session="", call=""):
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
                    "session": session,
                    "call": call,
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
            session = ""
            call = ""
            try:
                payload = json.load(sys.stdin)
                framework = str(payload.get("framework") or "opencode")
                tool = str(payload.get("tool", ""))
                session = str(payload.get("session", ""))
                call = str(payload.get("call", ""))
                event = str(payload.get("event", ""))
                workspace = str(payload.get("workspace", ""))
                with contextlib.redirect_stdout(sys.stderr):
                    from plugins.blackbox.guard import hooks as guard

                    if event == "session_start":
                        if hasattr(guard, "on_session_start"):
                            guard.on_session_start(session_id=session, framework=framework, workspace=workspace)
                        record(framework, "SESSION_STARTED", "", "ok", "ok", 0, session=session)
                        print("{}")
                        return

                    if event == "pre_api_request":
                        if hasattr(guard, "on_pre_api_request"):
                            guard.on_pre_api_request(
                                user_message="",
                                request_messages=[],
                                session_id=session,
                                model=payload.get("model"),
                                provider=framework,
                                framework=framework,
                                workspace=workspace,
                            )
                        record(framework, "PROMPT_SCANNED", "", "ok", "ok", 0, session=session)
                        print("{}")
                        return

                    if event == "session_end":
                        if hasattr(guard, "on_session_end"):
                            guard.on_session_end(
                                session_id=session,
                                completed=True,
                                interrupted=False,
                                framework=framework,
                                workspace=workspace,
                            )
                        record(framework, "SESSION_ENDED", "", "ok", "ok", 0, session=session)
                        print("{}")
                        return

                    decision = guard.on_pre_tool_call(
                        tool_name=tool,
                        args=payload.get("args") or {},
                        session_id=session,
                        tool_call_id=call,
                    )
                blocked = bool(decision and decision.get("action") == "block")
                record(
                    framework,
                    "GUARD_BLOCKED" if blocked else "GUARD_ALLOWED",
                    tool,
                    "block" if blocked else "allowed",
                    "blocked" if blocked else "allowed",
                    int((time.monotonic() - started) * 1000),
                    session=session,
                    call=call)
                print(json.dumps(decision or {}))
            except Exception as exc:
                # Fail open: a Blackbox or bridge fault must not break the host agent.
                record(framework, "GUARD_FAILED", tool, "", "error",
                       int((time.monotonic() - started) * 1000), type(exc).__name__,
                       session=session, call=call)
                print("{}")


        if __name__ == "__main__":
            main()
        """;

    private static string JsPath(string path) =>
        path.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);
}
