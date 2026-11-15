// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Blackbox;

/// <summary>
/// Shared Python pre-tool command and tamper-protection helpers embedded across Axiom agent
/// lifecycle hooks so every supported host enforces consistent guard-tamper, protected-delete,
/// exfiltration, protected-launch, and escalation blocks prior to upstream hook evaluation.
/// </summary>
public static class AgentCommandGuard
{
    public const string PythonHelpers = """
        def _tampers_with_guard(command: str) -> bool:
            # An agent must not be able to delete, overwrite, or strip permissions on the local
            # guard, its hooks, or the bridge across any supported host harness.
            text = " ".join((command or "").lower().split())
            markers = (
                "plugins\\blackbox",
                "plugins/blackbox",
                "axiom-guard-bridge",
                "axiom-antigravity-hook",
                "axiom-claude-hook",
                "axiom-codex-hook",
                "axiom-cursor-hook",
                "axiom-windsurf-hook",
                "axiom-gemini-hook",
                "axiom-cline-hook",
                "axiom-copilot-hook",
                "axiom-deepseek-hook",
                "axiom-zcode-hook",
                ".hermes\\blackbox",
                ".hermes/blackbox",
                "hermes\\blackbox",
                "hermes/blackbox",
                "axiom\\modules\\blackbox",
                "axiom/modules/blackbox",
                "hooks.json",
            )
            verbs = (
                "del ",
                "erase ",
                "rm ",
                "rmdir",
                "move ",
                "ren ",
                "remove-item",
                "move-item",
                "rename-item",
                "copy-item",
                "set-content",
                "add-content",
                "out-file",
                "clear-content",
                "unlink ",
                ">",
                "copy ",
                "icacls ",
                "chmod ",
                "shutil.rmtree",
                "os.remove",
                "os.unlink",
            )
            if not any(marker in text for marker in markers):
                return False
            return any(verb in text for verb in verbs)


        def _deletes_protected(command: str, protected) -> bool:
            # True when a shell command deletes one of the operator's protected files.
            # Blackbox's custom file-access detector covers reads and copies; a shell
            # del/rm/Remove-Item of a protected path would otherwise pass.
            text = " ".join((command or "").lower().split())
            verbs = ("del ", "erase ", "rm ", "rmdir", "remove-item", "unlink ")
            if not any(verb in text for verb in verbs):
                return False
            return _hits_protected(text, protected)


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
            text = (command or "").lower()
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
            # matched the argument (curl -F file=@... was allowed in the lab).
            text = " ".join((command or "").lower().split())
            if not _hits_protected(text, protected):
                return False
            if any(client in text for client in ("scp ", "sftp ", "ftp ")):
                return True
            clients = ("curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod", "certutil")
            flags = (" -f", "--form", "-d @", "--data @", "-t ", "--upload-file", "-infile",
                     "--post-file", "-encode", "upload")
            return any(client in text for client in clients) and any(flag in text for flag in flags)


        def _escalation_risk(command: str) -> str:
            # Remote-script execution and LOLBin download/persistence shapes. Returns a short
            # label for a block, or "" when the command is not one of these shapes.
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
            if ("powershell" in text or "pwsh" in text) and (
                "-enc " in text or text.endswith("-enc") or "-encodedcommand" in text
            ):
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


        def _load_protected_paths():
            try:
                from plugins.blackbox.kernel.config import load_blackbox_config
                return load_blackbox_config().protected_paths
            except Exception:
                return ()


        def _command_text(args) -> str:
            if not isinstance(args, dict):
                return ""
            for key in ("command", "CommandLine", "command_line", "cmd"):
                value = args.get(key)
                if isinstance(value, str) and value.strip():
                    return value
            return ""


        def _check_command_safety(args, protected=None):
            command_text = _command_text(args)
            if not command_text:
                return None
            if protected is None:
                protected = _load_protected_paths()
            if _tampers_with_guard(command_text):
                return ("tamper", "Blackbox blocked this call: it modifies the local guard.")
            if _deletes_protected(command_text, protected):
                return ("delete", "Blackbox blocked this call: it deletes a protected path.")
            if _exfiltrates_protected(command_text, protected):
                return ("exfiltration", "Blackbox blocked this call: it uploads a file from a protected path.")
            if _executes_protected(command_text, protected):
                return ("execution", "Blackbox blocked this call: it launches a file from a protected path.")
            escalation = _escalation_risk(command_text)
            if escalation:
                return ("escalation", f"Blackbox blocked this call: {escalation}.")
            return None
        """;
}
