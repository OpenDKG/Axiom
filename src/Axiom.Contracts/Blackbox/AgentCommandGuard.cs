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
            # del/rm/Remove-Item of a protected path would otherwise pass.
            text = " ".join((command or "").lower().split())
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


        def _sensitive_store(text: str) -> str:
            # Credential stores the vendor's protected list does not name. The sweep found reads
            # of these allowed: .git-credentials, .npmrc, .kube/config, GitHub CLI hosts.yml,
            # browser Login Data/Cookies and extension storage, Firefox profiles, wallet files.
            value = _normalize_command(text)
            stores = (
                (".git-credentials", "Git credential store"),
                (".npmrc", "npm token store"),
                (".kube\\config", "Kubernetes config"),
                ("github cli\\hosts.yml", "GitHub CLI token"),
                (".docker\\config.json", "Docker credential store"),
                ("\\login data", "browser login database"),
                ("\\network\\cookies", "browser cookie database"),
                ("local extension settings", "browser extension storage"),
                ("mozilla\\firefox\\profiles", "Firefox profile store"),
                ("wallet.dat", "wallet file"),
            )
            for marker, label in stores:
                if marker in value:
                    return label
            return ""


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
            # matched the argument (curl -F file=@... was allowed in the lab).
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
            if "reg save" in text and any(hive in text for hive in ("hklm\\sam", "hklm\\security", "hklm\\system")):
                return "credential hive export"
            if "vssadmin" in text and "create shadow" in text:
                return "shadow-copy creation"
            if "ntdsutil" in text:
                return "NTDS dump"
            if "lsass" in text and any(tool in text for tool in ("procdump", "comsvcs", "minidump", "rundll32")):
                return "LSASS memory dump"
            if ("wevtutil" in text and (" cl " in text or "clear-log" in text)) or "clear-eventlog" in text:
                return "event log clearing"
            if "set-mppreference" in text and any(
                flag in text
                for flag in ("disablerealtimemonitoring", "disableantispyware",
                             "disableioavprotection", "disablescriptscanning")
            ):
                return "Defender tampering"
            if "add-mppreference" in text and "exclusion" in text:
                return "Defender exclusion"
            if "netsh advfirewall" in text and "state off" in text:
                return "firewall tampering"
            if "netsh firewall" in text and "opmode disable" in text:
                return "firewall tampering"
            if "register-scheduledtask" in text:
                return "scheduled-task persistence (PowerShell)"
            if ("new-itemproperty" in text or "set-itemproperty" in text) and "\\currentversion\\run" in text:
                return "registry run-key persistence (PowerShell)"
            if "sc create" in text or "new-service" in text:
                return "service creation"
            if "startup" in text and any(
                verb in text for verb in ("copy ", "move ", "set-content", "out-file", "new-item", "add-content", ">")
            ):
                return "startup folder persistence"
            if "wmic process call create" in text:
                return "WMI process creation"
            if "downloadstring" in text and ("iex" in text or "invoke-expression" in text):
                return "download-and-execute"
            if "add-type" in text and "typedefinition" in text:
                return "in-memory compile"
            if any(host in text for host in ("wscript", "cscript")) and any(
                ext in text for ext in (".vbs", ".js", ".wsf")
            ):
                return "script host execution"
            if "mshta" in text and "vbscript" in text:
                return "mshta vbscript"
            if "cmdkey" in text and "/list" in text:
                return "credential enumeration (cmdkey)"
            if "vaultcmd" in text:
                return "credential enumeration (vaultcmd)"
            if "netsh wlan" in text and "key=clear" in text:
                return "Wi-Fi key extraction"
            if "export-certificate" in text or ("certutil" in text and "-exportpfx" in text):
                return "certificate export"
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
            store = _sensitive_store(command_text)
            if not store and isinstance(args, dict):
                store = _sensitive_store(str(args.get("path") or args.get("filePath") or ""))
            if store:
                return ("credential-store", f"Blackbox blocked this call: it accesses a credential store ({store}).")
            if _tampers_with_guard(command_text):
                return ("tamper", "Blackbox blocked this call: it modifies the local guard.")
            if _deletes_protected(command_text, protected):
                return ("delete", "Blackbox blocked this call: it deletes a protected path.")
            if _hidden_path_read(command_text, protected):
                return ("read", "Blackbox blocked this call: it reads a protected path through a hidden path form.")
            if _tampers_with_protected(command_text, protected):
                return ("permissions", "Blackbox blocked this call: it changes ownership or permissions of a protected path.")
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
