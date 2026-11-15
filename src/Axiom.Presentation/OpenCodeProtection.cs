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
              // OpenCode 2 also loads flat plugin files and requires a server() member. The
              // directory plugin is the V2 entrypoint, so this legacy file deliberately does
              // nothing there instead of registering the guard twice.
              async server() {
              },
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
            child.on("error", () => {})
            if (child.stdin) {
              child.stdin.on("error", () => {})
              child.stdin.write(JSON.stringify(payload))
              child.stdin.end()
            }
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
              // Forward the user text so the guard can scan it for injection. Event shapes vary
              // by harness version; anything missing simply yields an empty string.
              let promptText = ""
              try {
                const parts = data.message?.parts || data.info?.parts || data.parts || []
                if (Array.isArray(parts)) {
                  promptText = parts
                    .filter((part) => part && part.type === "text" && typeof part.text === "string")
                    .map((part) => part.text)
                    .join("\n")
                }
                if (!promptText && typeof data.message?.text === "string") promptText = data.message.text
              } catch {
                promptText = ""
              }
              runLifecycleBridge({
                framework: "opencode",
                event: "pre_api_request",
                session,
                user_message: promptText,
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

          let retryDelay = 2000
          const connect = async () => {
            try {
              const response = await fetch(`http://127.0.0.1:${port}/api/event`, { headers })
              if (response.status === 401 || response.status === 403) {
                // The managed server rotates its password and a plugin worker may not see the
                // current value. Poll slowly instead of hammering the server every two seconds.
                retryDelay = 60000
                setTimeout(connect, retryDelay)
                return
              }
              if (!response.ok || !response.body) throw new Error("event stream unavailable")
              retryDelay = 2000
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


        def _tampers_with_guard(command: str) -> bool:
            # An agent must not be able to delete or rewrite the local guard, its hooks or the
            # bridge. Blackbox's own tamper detector did not catch a plain delete in the lab.
            text = (command or "").lower()
            markers = ("plugins\\blackbox", "plugins/blackbox", "axiom-guard-bridge", ".hermes\\blackbox", ".hermes/blackbox")
            verbs = ("del ", "erase ", "rm ", "rmdir ", "move ", "ren ", "remove-item", "unlink ", ">", "copy ")
            if not any(marker in text for marker in markers):
                return False
            return any(verb in text for verb in verbs)


        def _normalize_command(command: str) -> str:
            # Shell variables and Win32 prefixes hide a protected path from token matching:
            # `cat "$HOME/.ssh/id_rsa"` and `type \\?\C:\...` were allowed while the literal
            # form blocked. Expand them before any path check runs.
            text = (command or "").lower()
            home = os.path.normpath(str(Path.home())).lower()
            profile = (os.environ.get("USERPROFILE") or str(Path.home())).lower()
            replacements = {
                "$env:userprofile": profile,
                "%userprofile%": profile,
                "$env:localappdata": (os.environ.get("LOCALAPPDATA") or "").lower(),
                "%localappdata%": (os.environ.get("LOCALAPPDATA") or "").lower(),
                "$env:appdata": (os.environ.get("APPDATA") or "").lower(),
                "%appdata%": (os.environ.get("APPDATA") or "").lower(),
                "${home}": home,
                "$home": home,
                "%home%": home,
            }
            for key, value in replacements.items():
                if value:
                    text = text.replace(key, value)
            text = text.replace("\\\\?\\", "").replace("//?/", "").replace("\\\\.\\", "")
            text = text.replace("~/", home + "\\").replace("~\\", home + "\\")
            return " ".join(text.split())


        def _deletes_protected(command: str, protected) -> bool:
            # True when a shell command deletes one of the operator's protected files.
            # Blackbox's custom file-access detector covers reads and copies; a shell
            # del/rm/Remove-Item of a protected path would otherwise pass. Use the same
            # path tokens as the launch/upload checks so wildcard directories such as
            # ~/.ssh/* are covered (the old stem match skipped them).
            text = (command or "").lower()
            verbs = ("del ", "erase ", "rm ", "rmdir", "remove-item", "unlink ",
                     "move ", "move-item", "ren ", "rename ", "rename-item", "mv ")
            if not any(verb in text for verb in verbs):
                return False
            return _hits_protected(text, protected)


        def _hidden_path_read(command: str, protected) -> bool:
            # Blackbox blocks a literal read of a protected path. The same read written with a
            # shell variable or a Win32 prefix ($HOME/.ssh, %USERPROFILE%\.ssh, \\?\C:\...)
            # passed. Only commands that actually hide a path are checked, so a literal
            # `.env.example` read is not a false positive.
            raw = (command or "").lower()
            hidden = ("$home", "%userprofile%", "$env:userprofile", "$env:localappdata",
                      "%localappdata%", "$env:appdata", "%appdata%", "~/", "~\\", "\\\\?\\", "//?/")
            if not any(marker in raw for marker in hidden):
                return False
            text = _normalize_command(raw)
            if not _hits_protected(text, protected):
                return False
            verbs = ("cat ", "type ", "more ", "head ", "tail ", "get-content", "readalltext",
                     "open(", ".read(", "copy ", "cp ", "get-item", "strings ", "forfiles")
            return any(verb in text for verb in verbs)


        def _tampers_with_protected(command: str, protected) -> bool:
            # Ownership or ACL changes on a protected file let the agent read or copy it after
            # the fact (takeown/icacls/attrib passed while a plain read blocked).
            text = _normalize_command(command)
            verbs = ("takeown", "icacls", "cacls", "attrib", "set-acl", "get-acl", "setaccessrule")
            return any(verb in text for verb in verbs) and _hits_protected(text, protected)


        def _protected_tokens(protected) -> list:
            # Tokens that identify a protected path inside a shell command. A trailing * uses its
            # parent directory (~/.ssh/* -> .ssh, C:\Lab\samples\* -> samples); a file pattern keeps
            # its leading dot (.env, .pem) so short names do not match unrelated binaries.
            tokens = []
            for pattern in protected or ():
                normalized = str(pattern).replace("~", "").replace("/", "\\").strip()
                parts = [part for part in normalized.split("\\") if part and part != "*"]
                if not parts:
                    continue
                tail = parts[-1]
                if tail == "*":
                    if len(parts) >= 2:
                        tokens.append(parts[-2].lower())
                    continue
                token = tail.rstrip("*").rstrip(".").lower()
                if token:
                    tokens.append(token)
            return [token for token in tokens if token]


        def _hits_protected(command: str, protected) -> bool:
            text = _normalize_command(command)
            return any(token in text for token in _protected_tokens(protected))


        def _executes_protected(command: str, protected) -> bool:
            # An agent must not launch a file that lives in a protected path: reading and copying
            # are covered by Blackbox, but Start-Process/&/cmd on the same file was allowed.
            text = " ".join((command or "").lower().split())
            if not _hits_protected(text, protected):
                return False
            verbs = ("start-process", "invoke-item", "cmd /c", "cmd.exe /c", "powershell", "pwsh",
                     "rundll32", "regsvr32", "mshta", "wmic process call create", "schtasks /run",
                     "& ", "&& ")
            return any(verb in text for verb in verbs)


        def _exfiltrates_protected(command: str, protected) -> bool:
            # Uploading or encoding a protected file is exfiltration even when no file-access rule
            # matched the argument (curl -F file=@… was allowed in the lab).
            text = " ".join((command or "").lower().split())
            if not _hits_protected(text, protected):
                return False
            if any(client in text for client in ("scp ", "sftp ", "ftp ")):
                return True
            clients = ("curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod", "certutil",
                       "python", "python3")
            flags = (" -f", "--form", "-d @", "--data @", "--data-binary", "-t ", "--upload-file",
                     "-infile", "--post-file", "-encode", "upload", "requests.post", ".read()")
            return any(client in text for client in clients) and any(flag in text for flag in flags)


        def _escalation_risk(command: str) -> str:
            # Remote-script execution and LOLBin download/persistence shapes. The pinned
            # verified ruleset has no confirmed escalation rules yet (that needs a curator
            # identity), so these high-risk agent actions would otherwise pass. Returns a
            # short label for a block, or "" when the command is not one of these shapes.
            text = " ".join((command or "").lower().split())
            if not text:
                return ""
            text = text.replace(" |", "|").replace("| ", "|")
            download = ("curl ", "wget ", "iwr ", "irm ", "invoke-webrequest",
                        "invoke-restmethod", "bitsadmin")
            pipe = ("|sh", "|bash", "|zsh", "|pwsh", "|powershell", "|python",
                    "|node", "|iex", "invoke-expression")
            if any(token in text for token in download) and any(token in text for token in pipe):
                return "remote script piped into a shell"
            if "base64" in text and any(token in text for token in pipe):
                return "base64 payload piped into a shell"
            if "certutil" in text and ("-urlcache" in text or "-verifyctl" in text or "-decode" in text):
                return "certutil download or decode"
            if "bitsadmin" in text and "/transfer" in text:
                return "bitsadmin transfer"
            if "mshta" in text and "http" in text:
                return "mshta remote script"
            if ("rundll32" in text or "regsvr32" in text) and "http" in text:
                return "LOLBin remote script"
            if ("powershell" in text or "pwsh" in text) and ("-enc " in text or "-encodedcommand" in text):
                return "encoded PowerShell"
            if "reg add" in text and "\\currentversion\\run" in text:
                return "registry run-key persistence"
            if "schtasks" in text and "/create" in text:
                return "scheduled-task persistence"
            if "vssadmin" in text and "delete" in text and "shadows" in text:
                return "shadow-copy deletion"
            if "wbadmin" in text and "delete catalog" in text:
                return "backup catalog deletion"
            if "bcdedit" in text and "recoveryenabled no" in text:
                return "recovery disable"
            return ""



        def _reexec_committed_interpreter() -> None:
            # The plugin starts this bridge with the vendor venv python. Hermes' package manager
            # commits a different dependency environment and activate_dependencies swaps sys.path
            # to it, so a venv built for another Python minor imports compiled packages for the
            # wrong ABI (pydantic_core, _cffi_backend). Re-exec the committed interpreter once so
            # the guard imports cleanly and no detector is skipped.
            if os.environ.get("AXIOM_BRIDGE_REEXEC") == "1":
                return
            local = os.environ.get("LOCALAPPDATA") or str(Path.home())
            candidates = []
            try:
                for install in (Path(local) / "hermes" / "installs").glob("*"):
                    facts = install / "facts.json"
                    if facts.is_file():
                        try:
                            data = json.loads(facts.read_text(encoding="utf-8"))
                            env = (data.get("packages") or {}).get("venv", {}).get("environment")
                            if env:
                                candidates.append(Path(env) / "Scripts" / "python.exe")
                        except Exception:
                            pass
                    envs = install / "environments"
                    if envs.is_dir():
                        for env in sorted(envs.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True):
                            candidates.append(env / "venv" / "Scripts" / "python.exe")
            except Exception:
                return
            current = os.path.normcase(os.path.abspath(sys.executable))
            for candidate in candidates:
                try:
                    if not candidate.is_file():
                        continue
                    target = os.path.normcase(os.path.abspath(str(candidate)))
                    if target == current:
                        continue
                    os.environ["AXIOM_BRIDGE_REEXEC"] = "1"
                    os.execv(str(candidate), [str(candidate), os.path.abspath(__file__), *sys.argv[1:]])
                except Exception:
                    continue


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


        def _quarantine_session(session: str, identifiers) -> None:
            # A confirmed (or high-severity) prompt-injection finding blocks the session's tools
            # until the window expires; the vendor prompt hook is observer-only.
            try:
                marker = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Axiom" / "injection-quarantine.json"
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.write_text(json.dumps({"session": session, "at": time.time(), "ids": list(identifiers)}))
            except Exception:
                pass


        def _is_quarantined(session: str) -> bool:
            try:
                marker = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Axiom" / "injection-quarantine.json"
                data = json.loads(marker.read_text())
                if str(data.get("session") or "") != session:
                    return False
                return (time.time() - float(data.get("at") or 0)) < 900
            except Exception:
                return False


        def main() -> None:
            _reexec_committed_interpreter()
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
                        user_text = str(payload.get("user_message") or "")
                        request_messages = payload.get("request_messages") or []
                        if hasattr(guard, "on_pre_api_request"):
                            guard.on_pre_api_request(
                                user_message=user_text,
                                request_messages=request_messages,
                                session_id=session,
                                model=payload.get("model"),
                                provider=framework,
                                framework=framework,
                                workspace=workspace,
                            )
                        if user_text:
                            # The vendor prompt hook is observer-only. Axiom applies its own
                            # policy: a high/critical injection finding quarantines the session,
                            # so the agent cannot act on the injected instruction.
                            try:
                                from plugins.blackbox.guard import api_request as _api_request
                                from plugins.blackbox.guard import graph_rules as _graph_rules
                                from plugins.blackbox.kernel.config import load_blackbox_config
                                cfg = load_blackbox_config()
                                rs, _ = _graph_rules.detection_rules(cfg, "", {})
                                sources = _api_request._untrusted_request_sources(user_text, request_messages)
                                findings = _api_request._injection_by_source(sources, rs, cfg.discover)
                                blocking = [
                                    f for f in findings
                                    if str(getattr(f, "category", "")) == "injection"
                                    and str(getattr(f, "severity", "")).lower() in ("high", "critical")
                                ]
                                if blocking:
                                    _quarantine_session(session, [getattr(f, "identifier", "") for f in blocking])
                                    record(framework, "GUARD_BLOCKED", "", "block", "blocked", 0, "", session)
                                    print(json.dumps({"action": "block", "message": "Prompt injection detected; the session is quarantined."}))
                                    return
                            except Exception:
                                pass
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

                    raw_args = payload.get("args") or {}
                    if isinstance(raw_args, dict) and "filePath" in raw_args and "path" not in raw_args:
                        # OpenCode names the file argument filePath; Blackbox's detectors read
                        # "path" (action_parsing._PATH_KEYS is case-sensitive), so a raw
                        # pass-through misses every file-access rule.
                        raw_args = {**raw_args, "path": raw_args["filePath"]}
                    try:
                        from plugins.blackbox.kernel.config import load_blackbox_config
                        protected = load_blackbox_config().protected_paths
                    except Exception:
                        protected = ()
                    command_text = str(raw_args.get("command") or "") if isinstance(raw_args, dict) else ""
                    if _is_quarantined(session):
                        record(framework, "GUARD_BLOCKED", tool, "block", "blocked", 0, "", session, call)
                        print(json.dumps({"action": "block", "message": "Session quarantined after a prompt-injection finding."}))
                        return
                    if _tampers_with_guard(command_text):
                        record(framework, "GUARD_BLOCKED", tool, "block", "blocked", 0, "", session, call)
                        print(json.dumps({"action": "block", "message": "Blackbox blocked this call: it modifies the local guard."}))
                        return
                    if _deletes_protected(command_text, protected):
                        record(framework, "GUARD_BLOCKED", tool, "block", "blocked", 0, "", session, call)
                        print(json.dumps({"action": "block", "message": "Blackbox blocked this call: it deletes a protected path."}))
                        return
                    if _hidden_path_read(command_text, protected):
                        record(framework, "GUARD_BLOCKED", tool, "block", "blocked", 0, "", session, call)
                        print(json.dumps({"action": "block", "message": "Blackbox blocked this call: it reads a protected path through a hidden path form."}))
                        return
                    if _tampers_with_protected(command_text, protected):
                        record(framework, "GUARD_BLOCKED", tool, "block", "blocked", 0, "permissions", session, call)
                        print(json.dumps({"action": "block", "message": "Blackbox blocked this call: it changes ownership or permissions of a protected path."}))
                        return
                    if _exfiltrates_protected(command_text, protected):
                        record(framework, "GUARD_BLOCKED", tool, "block", "blocked", 0, "exfiltration", session, call)
                        print(json.dumps({"action": "block", "message": "Blackbox blocked this call: it uploads a file from a protected path."}))
                        return
                    if _executes_protected(command_text, protected):
                        record(framework, "GUARD_BLOCKED", tool, "block", "blocked", 0, "execution", session, call)
                        print(json.dumps({"action": "block", "message": "Blackbox blocked this call: it launches a file from a protected path."}))
                        return
                    escalation = _escalation_risk(command_text)
                    if escalation:
                        record(framework, "GUARD_BLOCKED", tool, "block", "blocked", 0, "escalation", session, call)
                        print(json.dumps({"action": "block", "message": f"Blackbox blocked this call: {escalation}."}))
                        return
                    decision = guard.on_pre_tool_call(
                        tool_name=tool,
                        args=raw_args,
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
