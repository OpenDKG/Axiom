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
        _MAX_SHELL_UNWRAP_DEPTH = 8


        def _split_shell_segments(command: str, _depth: int = 0) -> list:
            # Split compound shell commands on unquoted operators (;, &&, ||, |, newline)
            # and unwrap nested `cmd /c "..."` or `bash/sh/powershell/pwsh -c "..."` up to _MAX_SHELL_UNWRAP_DEPTH.
            raw = command or ""
            if not raw.strip():
                return []
            segments = []
            buf = []
            quote = ""
            i = 0
            n = len(raw)
            while i < n:
                ch = raw[i]
                if quote:
                    buf.append(ch)
                    if ch == quote:
                        quote = ""
                    i += 1
                    continue
                if ch in ("'", '"'):
                    quote = ch
                    buf.append(ch)
                    i += 1
                    continue
                if ch == "\n" or ch == "\r" or ch == ";":
                    part = "".join(buf).strip()
                    if part:
                        segments.append(part)
                    buf = []
                    i += 1
                    continue
                if raw.startswith("&&", i) or raw.startswith("||", i):
                    part = "".join(buf).strip()
                    if part:
                        segments.append(part)
                    buf = []
                    i += 2
                    continue
                if ch == "|":
                    part = "".join(buf).strip()
                    if part:
                        segments.append(part)
                    buf = []
                    i += 1
                    continue
                buf.append(ch)
                i += 1
            tail = "".join(buf).strip()
            if tail:
                segments.append(tail)

            expanded = []
            for seg in segments:
                expanded.append(seg)
                if _depth >= _MAX_SHELL_UNWRAP_DEPTH:
                    continue
                tokens = _tokenize_segment(seg)
                if len(tokens) >= 3:
                    head = os.path.basename(tokens[0][0].lower()).removesuffix(".exe")
                    if head in ("cmd", "bash", "sh", "zsh", "powershell", "pwsh", "python", "python3"):
                        for idx in range(1, len(tokens) - 1):
                            flag = tokens[idx][0].lower()
                            if flag in ("/c", "-c", "-command") and not tokens[idx][1]:
                                inner = tokens[idx + 1][0]
                                if inner:
                                    expanded.extend(_split_shell_segments(inner, _depth + 1))
                                break
            return expanded


        def _tokenize_segment(segment: str) -> list:
            # Returns list of (token_text, was_quoted) preserving backslashes for Windows paths.
            tokens = []
            buf = []
            quote = ""
            had_quote = False
            in_tok = False
            for ch in (segment or ""):
                if quote:
                    if ch == quote:
                        quote = ""
                    else:
                        buf.append(ch)
                    continue
                if ch in ("'", '"'):
                    quote = ch
                    had_quote = True
                    in_tok = True
                    continue
                if ch.isspace():
                    if in_tok:
                        tokens.append(("".join(buf), had_quote))
                        buf = []
                        had_quote = False
                        in_tok = False
                    continue
                buf.append(ch)
                in_tok = True
            if in_tok:
                tokens.append(("".join(buf), had_quote))
            return tokens


        def _segment_verbs(segment: str) -> tuple:
            # Extract whole-word command names and two-word subcommands from unquoted structure.
            # Prevents substring false positives like "confirm " -> "rm " or "model " -> "del ".
            tokens = _tokenize_segment(segment)
            verbs = set()
            unquoted_words = []
            first_word = ""
            skip_wrappers = {"sudo", "env", "command", "nohup", "&"}
            idx = 0
            while idx < len(tokens):
                tok, quoted = tokens[idx]
                low = tok.lower()
                if not quoted and (low in skip_wrappers or ("=" in low and not low.startswith("-") and idx == 0)):
                    idx += 1
                    continue
                break
            if idx < len(tokens):
                head = os.path.basename(tokens[idx][0].lower())
                first_word = head
                verbs.add(head)
                verbs.add(head.removesuffix(".exe"))
                if idx + 1 < len(tokens) and not tokens[idx + 1][1]:
                    sub = tokens[idx + 1][0].lower()
                    verbs.add(f"{head.removesuffix('.exe')} {sub}")
                # Check for cmd /c <verb> style unquoted remainder
                if head.removesuffix(".exe") == "cmd":
                    for j in range(idx + 1, len(tokens) - 1):
                        if tokens[j][0].lower() in ("/c", "/k") and not tokens[j][1]:
                            nxt = os.path.basename(tokens[j + 1][0].lower())
                            verbs.add(nxt)
                            verbs.add(nxt.removesuffix(".exe"))
                            break
            for tok, quoted in tokens:
                if not quoted:
                    low = tok.lower()
                    unquoted_words.append(low)
                    for part in low.replace("(", " ").replace(")", " ").replace(".", " ").split():
                        unquoted_words.append(part)
            return first_word, verbs, set(unquoted_words)


        def _has_command_verb(command: str, verbs) -> bool:
            import re as _re
            targets = {v.strip().lower() for v in verbs if v.strip()}
            for seg in _split_shell_segments(command):
                first_word, cmd_verbs, unquoted_words = _segment_verbs(seg)
                low_seg = " ".join((seg or "").lower().split())
                for target in targets:
                    if target == ">":
                        if _re.search(r"(?:^|[\s\d])>{1,2}\s*[^\s;&|]+", low_seg):
                            return True
                        continue
                    if " " in target:
                        if target in cmd_verbs:
                            return True
                        # Match unquoted multi-word invocation outside quoted strings
                        unquoted_only = " ".join(w for w, q in _tokenize_segment(seg) if not q).lower()
                        if _re.search(r"(?<![a-z0-9_-])" + _re.escape(target) + r"(?![a-z0-9_-])", unquoted_only):
                            return True
                    elif target.startswith(".") or target.endswith("("):
                        if target in low_seg:
                            return True
                    else:
                        if target in cmd_verbs:
                            return True
                        # Also catch inline function/cmdlet verbs in unquoted position or PowerShell subexpressions
                        unquoted_only = " ".join(w for w, q in _tokenize_segment(seg) if not q).lower()
                        if target in unquoted_words or _re.search(r"(?<![a-z0-9_-])" + _re.escape(target) + r"(?![a-z0-9_-])", unquoted_only):
                            return True
            return False


        def _has_redirection_to(command: str, markers) -> bool:
            import re as _re
            for seg in _split_shell_segments(command):
                norm_seg = seg.lower().replace("/", "\\")
                for m in _re.finditer(r"(?:^|[\s\d])>{1,2}\s*([^\s;&|]+)", norm_seg):
                    target = m.group(1).strip("\"'")
                    if any(marker in target for marker in markers):
                        return True
            return False


        def _tampers_with_guard(command: str) -> bool:
            # Match guard files and agent harness hook configs specifically (never arbitrary
            # project files that merely happen to be named hooks.json).
            norm = _normalize_command(command).replace("/", "\\")
            markers = (
                "plugins\\blackbox",
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
                ".claude\\hooks.json",
                ".claude\\settings",
                ".codex\\hooks.json",
                ".cursor\\hooks.json",
                ".gemini\\settings",
                ".windsurf\\hooks.json",
                ".github\\hooks\\",
                ".clinerules\\",
                "hermes\\blackbox",
                "axiom\\modules\\blackbox",
                "hermes\\config.yaml",
                ".zcode\\cli\\config.json",
                "blackbox\\agent-blackbox\\hooks.json",
            )
            if not any(marker in norm for marker in markers):
                return False
            if _has_redirection_to(command, [m.replace("\\", "/") for m in markers] + list(markers)):
                return True
            verbs = (
                "del", "erase", "rm", "rmdir", "mv", "move", "ren", "rename",
                "remove-item", "move-item", "rename-item", "copy-item",
                "set-content", "add-content", "out-file", "clear-content",
                "unlink", "copy", "cp", "icacls", "chmod", "chown",
                "shutil.rmtree", "os.remove", "os.unlink",
            )
            return _has_command_verb(command, verbs)


        def _disables_guard(command: str) -> bool:
            # Service/process/task management targeting Axiom/Blackbox, or delete/ACL verbs
            # targeting actual Axiom install/data/evidence locations (never repo checkouts or temp builds).
            norm = _normalize_command(command).replace("/", "\\")
            if not norm:
                return False
            if "auditpol /clear" in norm or "shadowcopy delete" in norm or "wmic shadowcopy" in norm:
                return True
            service_verbs = (
                "sc stop", "sc delete", "stop-service", "restart-service", "set-service",
                "net stop", "taskkill", "schtasks /change", "schtasks /delete",
                "disable-scheduledtask", "unregister-scheduledtask",
                "systemctl stop", "systemctl disable", "launchctl unload", "launchctl bootout",
            )
            service_targets = (
                "axiom.service", "axiom.desktop", "axiomd", "com.axiom.service",
                "agent blackbox", "axiom-blackbox", "blackbox",
            )
            if _has_command_verb(command, service_verbs):
                unquoted = " ".join(w for seg in _split_shell_segments(norm) for w, q in _tokenize_segment(seg) if not q)
                words = set(unquoted.replace('"', " ").replace("'", " ").split())
                if "axiom" in words or any(t in unquoted for t in service_targets):
                    return True
            path_markers = (
                "appdata\\local\\axiom",
                "local\\axiom\\",
                ".local\\share\\axiom",
                "application support\\axiom",
                "programdata\\axiom",
                "program files\\axiom",
                "programs\\axiom",
                "axiom\\modules\\blackbox",
                "hermes\\blackbox",
                "plugins\\blackbox",
                "agent-evidence.jsonl",
                "guard-failure-policy.txt",
                "protection-status.json",
                "usr\\lib\\axiom-firewall",
                "usr\\libexec\\axiom",
                "var\\lib\\axiom",
                "etc\\axiom",
            )
            file_verbs = (
                "del", "erase", "rm", "rmdir", "remove-item", "unlink",
                "icacls", "chmod", "chown", "takeown",
            )
            return any(m in norm for m in path_markers) and _has_command_verb(command, file_verbs)


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
            verbs = ("del", "erase", "rm", "rmdir", "remove-item", "unlink",
                     "move", "move-item", "ren", "rename", "rename-item", "mv",
                     "shutil.rmtree", "os.remove", "os.unlink")
            if not _has_command_verb(command, verbs):
                return False
            return _hits_protected(command, protected)


        def _reads_protected(command: str, protected) -> bool:
            verbs = ("cat", "type", "more", "head", "tail", "get-content", "readalltext",
                     "open(", ".read(", "copy", "cp", "get-item", "strings", "forfiles",
                     "findstr", "select-string", "grep", "rg", "tar", "compress-archive",
                     "copy-item", "move-item", "robocopy", "xcopy", "openssl", "ssh-keygen",
                     "gpg", "age", "makecab", "expand", "esentutl", "ssh -i", "split", "csplit")
            if not _has_command_verb(command, verbs):
                return False
            text = _normalize_command(command)
            words = text.replace("\\", " ").replace("/", " ").replace('"', " ").replace("'", " ").split()
            tokens = _protected_tokens(protected)
            return any(word in tokens for word in words) or _glob_hits(text, tokens)


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
            verbs = ("cat", "type", "more", "head", "tail", "get-content", "readalltext",
                     "open(", ".read(", "copy", "cp", "get-item", "strings", "forfiles")
            return _has_command_verb(command, verbs)


        def _tampers_with_protected(command: str, protected) -> bool:
            verbs = ("takeown", "icacls", "cacls", "attrib", "set-acl", "get-acl", "setaccessrule")
            return _has_command_verb(command, verbs) and _hits_protected(command, protected)


        def _sensitive_store(text: str) -> str:
            # Credential stores the vendor's protected list does not name. The sweep found reads
            # of these allowed: .git-credentials, .npmrc, .kube/config, GitHub CLI hosts.yml,
            # browser Login Data/Cookies and extension storage, Firefox profiles, wallet files.
            value = _normalize_command(text).replace("/", "\\")
            stores = (
                (".git-credentials", "Git credential store"),
                (".aws", "AWS credential store"),
                (".gnupg", "GnuPG keyring"),
                (".npmrc", "npm token store"),
                (".kube\\config", "Kubernetes config"),
                ("github cli\\hosts.yml", "GitHub CLI token"),
                (".docker\\config.json", "Docker credential store"),
                ("\\login data", "browser login database"),
                ("\\network\\cookies", "browser cookie database"),
                ("local extension settings", "browser extension storage"),
                ("mozilla\\firefox\\profiles", "Firefox profile store"),
                ("wallet.dat", "wallet file"),
                (".netrc", "netrc credentials"),
                (".pgpass", "PostgreSQL password file"),
                (".vault-token", "Vault token"),
                (".config\\gcloud", "gcloud credentials"),
                (".azure", "Azure credentials"),
                (".password-store", "pass store"),
                ("key4.db", "Firefox key database"),
                ("logins.json", "Firefox login database"),
                ("\\web data", "browser autofill database"),
                ("user data\\local state", "browser encryption key"),
                ("\\microsoft\\protect", "DPAPI master-key store"),
                ("\\microsoft\\credentials", "DPAPI credential store"),
                ("\\panther\\unattend", "Windows unattend file"),
                ("defaultpassword", "Winlogon autologon password"),
                ("terraform.tfstate", "Terraform state (may hold secrets)"),
                (".terraformrc", "Terraform CLI token"),
                ("\\.pulumi", "Pulumi credential store"),
                ("gh\\hosts.yml", "GitHub CLI token"),
                ("slack\\tokens.json", "Slack token store"),
                ("\\discord\\local storage", "Discord local storage"),
                ("state.vscdb", "VS Code global state database"),
                (".kdbx", "KeePass database"),
                (".opvault", "1Password vault"),
                (".htpasswd", "Apache htpasswd file"),
                ("\\1password\\", "password manager store"),
                ("bitwarden", "password manager store"),
                ("keepass", "password manager store"),
            )
            for marker, label in stores:
                if marker in value:
                    return label
            if len(value) <= 4096 and "\n" not in value:
                if _glob_hits(value, [marker for marker, _ in stores]):
                    return "wildcard credential store"
            return ""


        def _glob_fullmatch(window: str, value: str) -> bool:
            # Match one wildcard spelling against the literal name it could resolve to. Reads done
            # with a wildcard (`type C:\Users\me\.ss?\id_rsa`, `...\*\Login Data`) never
            # contain the literal protected token, so a plain substring test misses them.
            import re as _re

            parts = []
            index = 0
            while index < len(window):
                char = window[index]
                if char == "*":
                    parts.append(".*")
                elif char == "?":
                    parts.append(".")
                elif char == "[":
                    end = window.find("]", index + 1)
                    if end < 0:
                        parts.append("\\[")
                    else:
                        inner = window[index + 1:end].replace("\\", "\\\\")
                        parts.append("[" + inner + "]")
                        index = end
                else:
                    parts.append(_re.escape(char))
                index += 1
            try:
                return _re.fullmatch("".join(parts), value, _re.IGNORECASE) is not None
            except _re.error:
                return False


        def _glob_hits(text: str, needles) -> bool:
            # True when a wildcard spelling in the command names one of the needles. Only windows
            # around each wildcard are tested, so a long tool argument stays cheap.
            text = (text or "").replace('"', " ").replace("'", " ")
            spots = [index for index, char in enumerate(text) if char in "*?["][:64]
            if not spots:
                return False
            for needle in needles:
                candidate = (needle or "").lower()
                if not candidate:
                    continue
                size = len(candidate)
                for spot in spots:
                    for start in range(max(0, spot - size + 1), spot + 1):
                        window = text[start:start + size]
                        # A character class spells one name character with several text
                        # characters (`[.]ssh`), so extend the window to its closing bracket.
                        closing = window.find("]")
                        if "[" in window and closing > 0:
                            window = text[start:start + size + closing]
                        if _glob_fullmatch(window, candidate):
                            return True
            return False


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
            tokens = _protected_tokens(protected)
            return any(token in text for token in tokens) or _glob_hits(text, tokens)


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
            if ("reg save" in text or "reg export" in text or "reg query" in text) and any(hive in text for hive in ("hklm\\sam", "hklm\\security", "hklm\\system")):
                return "credential hive export"
            if "vssadmin" in text and "create shadow" in text:
                return "shadow-copy creation"
            if "ntdsutil" in text:
                return "NTDS dump"
            if "fsutil" in text and "deletejournal" in text:
                return "USN journal deletion"
            if "cipher /w" in text:
                return "free-space wipe"
            if "export-pfxcertificate" in text:
                return "private-key certificate export"
            if "wmic" in text and ("commandlineeventconsumer" in text or "\\root\\subscription" in text):
                return "WMI event-consumer persistence"
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


        _DEFAULT_PROTECTED_PATHS = (
            "~/.ssh/*",
            "~/.gnupg/*",
            "~/.aws/*",
            "~/.azure/*",
            "~/.kube/*",
            "~/.config/gcloud/*",
            "~/.solana/*",
            "~/.config/solana/*",
            "~/.ethereum/*",
            "~/.bitcoin/*",
            "~/.electrum/*",
            "wallet.dat",
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
            ".env",
            ".env.local",
            ".env.production",
            ".npmrc",
            ".pypirc",
            ".git-credentials",
            ".netrc",
            ".pgpass",
            ".vault-token",
        )


        def _local_axiom_dirs() -> list:
            dirs = []
            if os.name == "nt":
                local = os.environ.get("LOCALAPPDATA")
                if local:
                    dirs.append(Path(local) / "Axiom")
            else:
                xdg = os.environ.get("XDG_DATA_HOME")
                if xdg:
                    dirs.append(Path(xdg) / "Axiom")
                dirs.append(Path.home() / ".local" / "share" / "Axiom")
                dirs.append(Path.home() / "Library" / "Application Support" / "Axiom")
            legacy = Path.home() / "Axiom"
            if legacy not in dirs:
                dirs.append(legacy)
            return dirs


        def _is_fail_closed() -> bool:
            env_flag = (os.environ.get("AXIOM_GUARD_FAIL_CLOSED") or "").strip().lower()
            if env_flag in ("1", "true", "yes", "fail-closed", "strict"):
                return True
            for axiom_dir in _local_axiom_dirs():
                policy_file = axiom_dir / "guard-failure-policy.txt"
                try:
                    if policy_file.is_file():
                        value = policy_file.read_text(encoding="utf-8-sig").strip().lower()
                        if value in ("fail-closed", "fail_closed", "strict", "true", "1"):
                            return True
                        if value in ("fail-open", "fail_open", "false", "0"):
                            return False
                except Exception:
                    pass
            if env_flag in ("0", "false", "no", "fail-open"):
                return False
            return False


        def _load_protected_paths():
            merged = list(_DEFAULT_PROTECTED_PATHS)
            seen = {item.lower() for item in merged}

            def add_path(candidate):
                if isinstance(candidate, str):
                    trimmed = candidate.strip()
                    if trimmed and trimmed.lower() not in seen:
                        seen.add(trimmed.lower())
                        merged.append(trimmed)

            try:
                from plugins.blackbox.kernel.config import load_blackbox_config
                for item in (load_blackbox_config().protected_paths or ()):
                    add_path(item)
            except ImportError:
                pass
            except Exception as exc:
                os.environ["AXIOM_BLACKBOX_CONFIG_ERROR"] = str(exc)

            candidates = [axiom_dir / "enforcement-policy.json" for axiom_dir in _local_axiom_dirs()]
            program_data = os.environ.get("ProgramData") or os.environ.get("PROGRAMDATA")
            if program_data:
                candidates.append(Path(program_data) / "Axiom" / "enforcement-policy.json")
            elif os.name != "nt":
                candidates.append(Path("/etc/axiom/enforcement-policy.json"))

            for policy_path in candidates:
                try:
                    if not policy_path.is_file():
                        continue
                    import json as _json
                    data = _json.loads(policy_path.read_text(encoding="utf-8-sig"))
                    if not isinstance(data, dict):
                        continue
                    for item in (data.get("protectedPaths") or ()):
                        add_path(item)
                    inner = data.get("policy")
                    if isinstance(inner, dict):
                        for res in (inner.get("resources") or ()):
                            if isinstance(res, dict):
                                add_path(res.get("scope"))
                except Exception:
                    continue

            return tuple(merged)


        def _arg_path(args) -> str:
            # Host tools disagree on the file argument name: OpenCode uses filePath, Codex
            # "path", Claude Code "file_path". The store check must see all three.
            if not isinstance(args, dict):
                return ""
            for key in ("path", "filePath", "file_path", "TargetFile", "AbsolutePath", "absolute_path"):
                value = args.get(key)
                if isinstance(value, str) and value.strip():
                    return value
            return ""


        def _command_text(args) -> str:
            if not isinstance(args, dict):
                return ""
            for key in ("command", "CommandLine", "command_line", "cmd"):
                value = args.get(key)
                if isinstance(value, str) and value.strip():
                    return value
            return ""


        def _flatten_args(value) -> str:
            # Concatenate every string value (and key) so a phrase split across fields or lines
            # still matches; the vendor's injection scan uses the same scope.
            parts = []

            def walk(item):
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    for key, child in item.items():
                        if isinstance(key, str):
                            parts.append(key)
                        walk(child)
                elif isinstance(item, (list, tuple)):
                    for child in item:
                        walk(child)

            walk(value)
            return "\n".join(parts)


        def _axiom_injection(value) -> str:
            # Axiom-owned phrasings the vendor's curated regexes missed in the lab: plain
            # "ignore previous instructions", "before answering, run ..." and zero-width
            # obfuscation between words. Returns the matched phrase for a named block.
            text = _flatten_args(value).lower()
            for mark in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"):
                text = text.replace(mark, "")
            phrases = (
                "ignore all previous instructions",
                "ignore previous instructions",
                "disregard previous instructions",
                "disregard prior instructions",
                "forget previous instructions",
                "ignore the above instructions",
                "before answering, run",
                "before answering run",
                "system override:",
                # Non-English phrasings the sweep found allowed; the vendor regexes are English-only.
                "zanemari prethodna uputstva",
                "zanemari sve prethodne instrukcije",
                "ignorisi prethodna uputstva",
                "ignoriere alle vorherigen anweisungen",
                "ignoriere vorherige anweisungen",
                "ignora las instrucciones anteriores",
                "ignora todas las instrucciones anteriores",
                "ignore les instructions precedentes",
                "ignorez les instructions precedentes",
                "ignora le istruzioni precedenti",
                "ignore as instrucoes anteriores",
                "игнорируй предыдущие инструкции",
                "игнорируй все предыдущие инструкции",
            )
            for phrase in phrases:
                if phrase in text:
                    return phrase
            return ""


        def _is_non_executable_doc_or_test_edit(args) -> bool:
            if not isinstance(args, dict) or _command_text(args):
                return False
            target = (_arg_path(args) or "").strip().lower().replace("/", "\\")
            if not target:
                return False
            blocked_names = ("claude.md", "agents.md", "gemini.md", ".cursorrules", "skill.md", "hooks.json")
            if any(target.endswith(b) for b in blocked_names):
                return False
            return target.endswith((".md", ".rst", ".txt", ".cs", ".py", ".ts", ".js", ".axaml")) and (
                "\\tests\\" in target or "\\docs\\" in target or target.endswith("test.cs") or target.endswith("tests.cs") or target.endswith("commandguard.cs")
            )


        def _check_command_safety(args, protected=None):
            injection = "" if _is_non_executable_doc_or_test_edit(args) else _axiom_injection(args)
            if injection:
                return ("injection-heuristic", "Blackbox blocked this call: prompt-injection phrasing in the tool arguments.")
            command_text = _command_text(args)
            arg_path = _arg_path(args)
            store = _sensitive_store(command_text)
            if not store:
                store = _sensitive_store(arg_path)
            if store:
                return ("credential-store", f"Blackbox blocked this call: it accesses a credential store ({store}).")
            if protected is None:
                protected = _load_protected_paths()
            if arg_path:
                norm_arg = _normalize_command(arg_path)
                tokens = _protected_tokens(protected)
                words = norm_arg.replace("\\", " ").replace("/", " ").replace('"', " ").replace("'", " ").split()
                if any(word in tokens for word in words) or _glob_hits(norm_arg, tokens):
                    return ("protected-path", "Blackbox blocked this call: it accesses a protected path.")
            if not command_text:
                return None
            if _tampers_with_guard(command_text):
                return ("tamper", "Blackbox blocked this call: it modifies the local guard.")
            if _disables_guard(command_text):
                return ("tamper", "Blackbox blocked this call: it stops or disables the local guard.")
            if _deletes_protected(command_text, protected):
                return ("delete", "Blackbox blocked this call: it deletes a protected path.")
            if _reads_protected(command_text, protected):
                return ("read", "Blackbox blocked this call: it reads a protected path.")
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
