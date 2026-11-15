// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class AgentHookScriptTests
{
    [Fact]
    public void Lifecycle_bridge_covers_prompt_tool_session_stop_and_apply_patch()
    {
        var codex = AgentHookScript.Build("codex");
        var claude = AgentHookScript.Build("claude");

        Assert.Contains("FRAMEWORK = \"codex\"", codex, StringComparison.Ordinal);
        Assert.Contains("FRAMEWORK = \"claude\"", claude, StringComparison.Ordinal);
        Assert.Contains("on_session_start", codex, StringComparison.Ordinal);
        Assert.Contains("on_pre_api_request", codex, StringComparison.Ordinal);
        Assert.Contains("on_pre_tool_call", codex, StringComparison.Ordinal);
        Assert.Contains("on_post_tool_call", codex, StringComparison.Ordinal);
        Assert.Contains("audit_stop", codex, StringComparison.Ordinal);
        Assert.Contains("PATCH_PATH", codex, StringComparison.Ordinal);
        Assert.Contains("tool_input", codex, StringComparison.Ordinal);
        Assert.Contains("\"decision\": \"block\"", codex, StringComparison.Ordinal);
        Assert.Contains("hookSpecificOutput", claude, StringComparison.Ordinal);
        Assert.DoesNotContain("{{", codex, StringComparison.Ordinal);
    }

    [Fact]
    public void OpenCode_bridge_normalizes_filePath_to_path()
    {
        // OpenCode passes filePath; Blackbox's detectors read only "path"
        // (action_parsing._PATH_KEYS is case-sensitive), so the bridge must translate it
        // or every file-access rule silently misses.
        var build = typeof(OpenCodeProtection).GetMethod(
            "BuildBridge",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var bridge = (string)build.Invoke(null, null)!;

        Assert.Contains("raw_args[\"filePath\"]", bridge, StringComparison.Ordinal);
        Assert.Contains("\"path\": raw_args[\"filePath\"]", bridge, StringComparison.Ordinal);
        Assert.Contains("args=raw_args", bridge, StringComparison.Ordinal);
        Assert.Contains("_deletes_protected", bridge, StringComparison.Ordinal);
        Assert.Contains("_tampers_with_guard", bridge, StringComparison.Ordinal);
        Assert.Contains("_escalation_risk", bridge, StringComparison.Ordinal);
        Assert.DoesNotContain("args=payload.get", bridge, StringComparison.Ordinal);
    }

    [Fact]
    public void OpenCode_bridge_carries_remote_script_and_persistence_detection()
    {
        var build = typeof(OpenCodeProtection).GetMethod(
            "BuildBridge",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var bridge = (string)build.Invoke(null, null)!;

        Assert.Contains("def _escalation_risk(command: str) -> str:", bridge, StringComparison.Ordinal);
        Assert.Contains("escalation = _escalation_risk(command_text)", bridge, StringComparison.Ordinal);
        Assert.Contains("\"escalation\"", bridge, StringComparison.Ordinal);

        string[] shapes =
        [
            "|sh", "|bash", "|pwsh", "|iex", "certutil", "-urlcache", "bitsadmin",
            "/transfer", "mshta", "reg add", "\\\\currentversion\\\\run", "schtasks",
            "/create", "vssadmin", "shadows", "bcdedit", "recoveryenabled no",
        ];
        foreach (var shape in shapes)
        {
            Assert.Contains(shape, bridge, StringComparison.Ordinal);
        }

        // The detector runs before the vendor guard so a missing verified rule cannot let a
        // remote pipe, encoded shell or persistence shape through.
        Assert.True(
            bridge.IndexOf("escalation = _escalation_risk", StringComparison.Ordinal) <
            bridge.IndexOf("guard.on_pre_tool_call", StringComparison.Ordinal));
    }

    [Fact]
    public void OpenCode_bridge_normalizes_path_variants_before_protected_path_checks()
    {
        var build = typeof(OpenCodeProtection).GetMethod(
            "BuildBridge",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var bridge = (string)build.Invoke(null, null)!;

        // Shell variables and Win32 prefixes previously hid a protected path from the token
        // match: `cat "$HOME/.ssh/id_rsa"`, `type %USERPROFILE%\...` and `\\?\C:\...` all
        // passed while the literal form blocked.
        Assert.Contains("def _normalize_command(command: str) -> str:", bridge, StringComparison.Ordinal);
        Assert.Contains("text = _normalize_command(command)", bridge, StringComparison.Ordinal);
        Assert.Contains("def _hidden_path_read(command: str, protected) -> bool:", bridge, StringComparison.Ordinal);
        Assert.Contains("_hidden_path_read(command_text, protected)", bridge, StringComparison.Ordinal);
        Assert.Contains("hidden path form", bridge, StringComparison.Ordinal);
        string[] expansions =
        [
            "\"$env:userprofile\"", "\"%userprofile%\"", "\"$env:localappdata\"",
            "\"%appdata%\"", "\"$home\"", "~/",
        ];
        foreach (var expansion in expansions)
        {
            Assert.Contains(expansion, bridge, StringComparison.Ordinal);
        }

        // move/rename of a protected file, and ownership/ACL tampering, are blocked with the
        // same protected-path tokens as read/copy.
        Assert.Contains("def _deletes_protected(command: str, protected) -> bool:", bridge, StringComparison.Ordinal);
        Assert.Contains("\"move-item\"", bridge, StringComparison.Ordinal);
        Assert.Contains("\"rename-item\"", bridge, StringComparison.Ordinal);
        Assert.Contains("def _tampers_with_protected(command: str, protected) -> bool:", bridge, StringComparison.Ordinal);
        Assert.Contains("_tampers_with_protected(command_text, protected)", bridge, StringComparison.Ordinal);
        Assert.Contains("\"takeown\"", bridge, StringComparison.Ordinal);
        Assert.Contains("\"icacls\"", bridge, StringComparison.Ordinal);
        Assert.Contains("\"attrib\"", bridge, StringComparison.Ordinal);
        Assert.Contains("ownership or permissions of a protected path", bridge, StringComparison.Ordinal);

        // Additional upload shapes observed in the lab.
        Assert.Contains("--data-binary", bridge, StringComparison.Ordinal);
        Assert.Contains("--upload-file", bridge, StringComparison.Ordinal);
        Assert.Contains("requests.post", bridge, StringComparison.Ordinal);

        Assert.True(
            bridge.IndexOf("_tampers_with_protected(command_text", StringComparison.Ordinal) <
            bridge.IndexOf("guard.on_pre_tool_call", StringComparison.Ordinal));
    }

    [Fact]
    public void OpenCode_bridge_carries_credential_evasion_and_persistence_detection()
    {
        var build = typeof(OpenCodeProtection).GetMethod(
            "BuildBridge",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var bridge = (string)build.Invoke(null, null)!;

        string[] labels =
        [
            "credential hive export", "shadow-copy creation", "NTDS dump", "LSASS memory dump",
            "event log clearing", "Defender tampering", "Defender exclusion", "firewall tampering",
            "scheduled-task persistence (PowerShell)", "registry run-key persistence (PowerShell)",
            "service creation", "startup folder persistence", "WMI process creation",
            "download-and-execute", "in-memory compile", "script host execution", "mshta vbscript",
        ];
        foreach (var label in labels)
        {
            Assert.Contains(label, bridge, StringComparison.Ordinal);
        }

        Assert.True(
            bridge.IndexOf("\"credential hive export\"", StringComparison.Ordinal) <
            bridge.IndexOf("guard.on_pre_tool_call", StringComparison.Ordinal));
    }

    [Fact]
    public void OpenCode_bridge_carries_credential_store_detection()
    {
        var build = typeof(OpenCodeProtection).GetMethod(
            "BuildBridge",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var bridge = (string)build.Invoke(null, null)!;

        // Credential stores outside the vendor's protected list: cloud/CLI tokens, browser
        // login/cookie databases, extension storage, Firefox profiles and wallet files.
        Assert.Contains("def _sensitive_store(text: str) -> str:", bridge, StringComparison.Ordinal);
        Assert.Contains("_sensitive_store(command_text)", bridge, StringComparison.Ordinal);
        string[] stores =
        [
            ".git-credentials", ".npmrc", ".kube\\\\config", "github cli\\\\hosts.yml",
            "\\\\login data", "\\\\network\\\\cookies", "local extension settings",
            "mozilla\\\\firefox\\\\profiles", "wallet.dat", "credential store",
            ".netrc", ".pgpass", ".vault-token", ".config\\\\gcloud", ".azure",
            ".password-store", "key4.db", "logins.json", "\\\\web data",
            "user data\\\\local state", "bitwarden", "keepass",
        ];
        foreach (var store in stores)
        {
            Assert.Contains(store, bridge, StringComparison.Ordinal);
        }

        // Credential enumeration shapes stay in the shared escalation detector.
        string[] labels =
        [
            "credential enumeration (cmdkey)", "credential enumeration (vaultcmd)",
            "Wi-Fi key extraction", "certificate export",
        ];
        foreach (var label in labels)
        {
            Assert.Contains(label, bridge, StringComparison.Ordinal);
        }

        Assert.True(
            bridge.IndexOf("_sensitive_store(command_text)", StringComparison.Ordinal) <
            bridge.IndexOf("guard.on_pre_tool_call", StringComparison.Ordinal));
    }

    [Fact]
    public void OpenCode_bridge_carries_injection_phrase_heuristics()
    {
        var build = typeof(OpenCodeProtection).GetMethod(
            "BuildBridge",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var bridge = (string)build.Invoke(null, null)!;

        // Phrasings the vendor's curated regexes missed: plain "ignore previous instructions",
        // "before answering, run ..." and zero-width obfuscation between words.
        Assert.Contains("def _axiom_injection(value) -> str:", bridge, StringComparison.Ordinal);
        Assert.Contains("def _flatten_args(value) -> str:", bridge, StringComparison.Ordinal);
        Assert.Contains("_axiom_injection(raw_args)", bridge, StringComparison.Ordinal);
        Assert.Contains("injection-heuristic", bridge, StringComparison.Ordinal);
        string[] phrases =
        [
            "ignore all previous instructions", "ignore previous instructions",
            "disregard previous instructions", "forget previous instructions",
            "before answering, run", "system override:", "\\u200b",
        ];
        foreach (var phrase in phrases)
        {
            Assert.Contains(phrase, bridge, StringComparison.Ordinal);
        }

        Assert.True(
            bridge.IndexOf("_axiom_injection(raw_args)", StringComparison.Ordinal) <
            bridge.IndexOf("guard.on_pre_tool_call", StringComparison.Ordinal));
    }

    [Fact]
    public void Gemini_hook_handles_before_tool_and_returns_gemini_deny()
    {
        var hook = AgentHookScript.Build("gemini");

        Assert.Contains("beforetool", hook, StringComparison.Ordinal);
        Assert.Contains("before_tool", hook, StringComparison.Ordinal);
        Assert.Contains("\"decision\": \"deny\"", hook, StringComparison.Ordinal);
        Assert.Contains("absolute_path", hook, StringComparison.Ordinal);
        Assert.Contains("args[\"path\"] = args[\"absolute_path\"]", hook, StringComparison.Ordinal);
    }

    [Fact]
    public void OpenCode_bridge_carries_launch_and_upload_protection()
    {
        var build = typeof(OpenCodeProtection).GetMethod(
            "BuildBridge",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var bridge = (string)build.Invoke(null, null)!;

        Assert.Contains("def _executes_protected(command: str, protected) -> bool:", bridge, StringComparison.Ordinal);
        Assert.Contains("def _exfiltrates_protected(command: str, protected) -> bool:", bridge, StringComparison.Ordinal);
        Assert.Contains("_executes_protected(command_text, protected)", bridge, StringComparison.Ordinal);
        Assert.Contains("_exfiltrates_protected(command_text, protected)", bridge, StringComparison.Ordinal);
        Assert.Contains("launches a file from a protected path", bridge, StringComparison.Ordinal);
        Assert.Contains("uploads a file from a protected path", bridge, StringComparison.Ordinal);
        Assert.Contains("return _hits_protected(text, protected)", bridge, StringComparison.Ordinal);
        Assert.True(
            bridge.IndexOf("_executes_protected(command_text", StringComparison.Ordinal) <
            bridge.IndexOf("guard.on_pre_tool_call", StringComparison.Ordinal));
    }

    [Fact]
    public void OpenCode_bridge_reexecs_the_committed_interpreter_before_reading_stdin()
    {
        var build = typeof(OpenCodeProtection).GetMethod(
            "BuildBridge",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var bridge = (string)build.Invoke(null, null)!;

        Assert.Contains("def _reexec_committed_interpreter() -> None:", bridge, StringComparison.Ordinal);
        Assert.Contains("_reexec_committed_interpreter()", bridge, StringComparison.Ordinal);
        Assert.Contains("AXIOM_BRIDGE_REEXEC", bridge, StringComparison.Ordinal);
        Assert.Contains("os.execv(", bridge, StringComparison.Ordinal);

        // The helper is defined and invoked before the guard imports and before stdin is read.
        Assert.True(
            bridge.IndexOf("os.execv(", StringComparison.Ordinal) <
            bridge.IndexOf("json.load(sys.stdin)", StringComparison.Ordinal));
    }

    [Fact]
    public void OpenCode_plugin_forwards_prompt_text_for_injection_scanning()
    {
        var build = typeof(OpenCodeProtection).GetMethod(
            "BuildV2Plugin",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        var plugin = (string)build.Invoke(new OpenCodeProtection(), null)!;

        Assert.Contains("user_message: promptText", plugin, StringComparison.Ordinal);
        Assert.Contains("part.type === \"text\"", plugin, StringComparison.Ordinal);
    }

    [Fact]
    public void OpenCode_bridge_compiles_when_python_is_available()
    {
        var python = FindPython();
        if (python is null)
        {
            return;
        }

        var build = typeof(OpenCodeProtection).GetMethod(
            "BuildBridge",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var bridge = (string)build.Invoke(null, null)!;
        var path = Path.Combine(Path.GetTempPath(), $"axiom-bridge-{Guid.NewGuid():N}.py");
        try
        {
            File.WriteAllText(path, bridge);
            var start = new ProcessStartInfo(python)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            start.ArgumentList.Add("-m");
            start.ArgumentList.Add("py_compile");
            start.ArgumentList.Add(path);
            using var process = Process.Start(start);
            Assert.NotNull(process);
            process.WaitForExit(15_000);
            Assert.True(process.HasExited, "Python syntax check did not finish.");
            Assert.Equal(0, process.ExitCode);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Guard_helpers_block_vectors_in_a_real_python_run()
    {
        var python = FindPython();
        if (python is null)
        {
            return;
        }

        var script = Axiom.Contracts.Blackbox.AgentCommandGuard.PythonHelpers + """


            import json
            import os
            from pathlib import Path

            failures = []

            def check(name, value, expected):
                if bool(value) != expected:
                    failures.append(name)

            check("store_git", _sensitive_store(r"C:\Users\lab\.git-credentials"), True)
            check("store_firefox", _sensitive_store(r"%APPDATA%\Mozilla\Firefox\Profiles\abc"), True)
            check("store_chrome", _sensitive_store(r"C:\Users\lab\AppData\Local\Google\Chrome\User Data\Default\Login Data"), True)
            check("store_benign", _sensitive_store(r"C:\Users\lab\notes.txt"), False)
            check("hidden_home", _hidden_path_read('cat "$HOME/.ssh/id_rsa"', (".ssh",)), True)
            check("hidden_extended", _hidden_path_read("type \\\\?\\C:\\Users\\lab\\.ssh\\id_rsa", (".ssh",)), True)
            check("hidden_benign", _hidden_path_read("cat notes.txt", (".ssh",)), False)
            check("tamper_takeown", _tampers_with_protected(r"takeown /f C:\Users\lab\.ssh\id_rsa", (".ssh",)), True)
            check("tamper_benign", _tampers_with_protected(r"takeown /f C:\Lab\x.txt", (".ssh",)), False)
            check("escalation_sam", _escalation_risk(r"reg save HKLM\SAM C:\x") == "credential hive export", True)
            check("escalation_cmdkey", _escalation_risk("cmdkey /list") == "credential enumeration (cmdkey)", True)
            check("escalation_benign", _escalation_risk("git status") == "", True)
            check("injection_ignore", _axiom_injection({"content": "Ignore previous instructions"}), True)
            check("injection_zero_width", _axiom_injection({"content": "ignore\u200b previous instructions"}), True)
            check("injection_benign", _axiom_injection({"command": "git status"}), False)
            check("safety_store_path", _check_command_safety({"path": r"C:\Users\lab\.git-credentials"}), True)
            check("safety_store_file_path", _check_command_safety({"file_path": r"C:\Users\lab\.git-credentials"}), True)
            check("safety_benign_path", _check_command_safety({"path": r"C:\Lab\notes.txt"}), False)
            check("safety_benign_command", _check_command_safety({"command": "git status"}), False)

            print(json.dumps({"failed": failures}))
            raise SystemExit(1 if failures else 0)
            """;

        var path = Path.Combine(Path.GetTempPath(), $"axiom-guard-{Guid.NewGuid():N}.py");
        try
        {
            File.WriteAllText(path, script);
            var start = new ProcessStartInfo(python)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            start.ArgumentList.Add(path);
            using var process = Process.Start(start);
            Assert.NotNull(process);
            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit(15_000);
            Assert.True(process.HasExited, "Python behaviour check did not finish.");
            Assert.True(process.ExitCode == 0, output + error);
            Assert.Contains("\"failed\": []", output, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Lifecycle_bridge_is_valid_python_when_python_is_available()
    {
        var python = FindPython();
        if (python is null)
        {
            return;
        }

        var path = Path.Combine(Path.GetTempPath(), $"axiom-hook-{Guid.NewGuid():N}.py");
        try
        {
            File.WriteAllText(path, AgentHookScript.Build("codex"));
            var start = new ProcessStartInfo(python)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            start.ArgumentList.Add("-m");
            start.ArgumentList.Add("py_compile");
            start.ArgumentList.Add(path);
            using var process = Process.Start(start);
            Assert.NotNull(process);
            process.WaitForExit(15_000);
            Assert.True(process.HasExited, "Python syntax check did not finish.");
            Assert.Equal(0, process.ExitCode);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Apply_patch_path_extraction_and_host_deny_shapes_match_each_host()
    {
        var python = FindPython();
        if (python is null)
        {
            return;
        }

        var directory = Path.Combine(Path.GetTempPath(), $"axiom-hook-contract-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var runner = Path.Combine(directory, "runner.py");
        try
        {
            File.WriteAllText(runner, """
                import importlib.util, json, sys
                path = sys.argv[1]
                spec = importlib.util.spec_from_file_location("axiom_hook_contract", path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                payload = json.loads(sys.argv[2])
                print(json.dumps({"args": module.tool_args(payload), "deny": module.deny("blocked")}))
                """);
            var payload = """{"tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Update File: C:\\work\\a.py\n*** End Patch"}}""";

            var codex = RunContract(python, runner, WriteScript(directory, "codex"), payload);
            Assert.Equal("C:\\work\\a.py", codex.RootElement.GetProperty("args").GetProperty("path").GetString());
            Assert.Equal("block", codex.RootElement.GetProperty("deny").GetProperty("decision").GetString());

            var claude = RunContract(python, runner, WriteScript(directory, "claude"), payload);
            Assert.Equal(
                "deny",
                claude.RootElement.GetProperty("deny").GetProperty("hookSpecificOutput").GetProperty("permissionDecision").GetString());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Ui_services_inline_protection_hooks_embed_command_guard_and_gemini_path_mapping()
    {
        var bindingFlags = System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static;
        var scripts = new (string Name, string Script)[]
        {
            ("GeminiProtection", (string)typeof(Axiom.UI.Services.GeminiProtection).GetMethod("BuildHookScript", bindingFlags)!.Invoke(null, null)!),
            ("AntigravityProtection", (string)typeof(Axiom.UI.Services.AntigravityProtection).GetMethod("BuildScript", bindingFlags)!.Invoke(null, null)!),
            ("CopilotProtection", (string)typeof(Axiom.UI.Services.CopilotProtection).GetMethod("BuildHookScript", bindingFlags)!.Invoke(null, null)!),
            ("CursorProtection", (string)typeof(Axiom.UI.Services.CursorProtection).GetMethod("BuildHookScript", bindingFlags)!.Invoke(null, null)!),
            ("WindsurfProtection", (string)typeof(Axiom.UI.Services.WindsurfProtection).GetMethod("BuildHookScript", bindingFlags)!.Invoke(null, null)!),
            (
                "ClineProtection",
                (string)typeof(Axiom.UI.Services.ClineProtection)
                    .GetMethod("BuildHookScript", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
                    .Invoke(new Axiom.UI.Services.ClineProtection(@"C:\temp\user", @"C:\temp\local"), null)!
            ),
        };

        foreach (var (name, script) in scripts)
        {
            Assert.True(
                script.Contains("def _check_command_safety(", StringComparison.Ordinal),
                $"{name} is missing injected AgentCommandGuard helpers.");
            Assert.True(
                script.Contains("_check_command_safety(", StringComparison.Ordinal),
                $"{name} never invokes _check_command_safety.");
            Assert.DoesNotContain("# <<AXIOM_COMMAND_GUARD>>", script, StringComparison.Ordinal);
        }

        var geminiScript = scripts[0].Script;
        Assert.Contains("parsed_args[\"path\"] = parsed_args[\"absolute_path\"]", geminiScript, StringComparison.Ordinal);
    }

    private static string WriteScript(string directory, string framework)
    {
        var path = Path.Combine(directory, framework + ".py");
        File.WriteAllText(path, AgentHookScript.Build(framework));
        return path;
    }

    private static System.Text.Json.JsonDocument RunContract(
        string python,
        string runner,
        string script,
        string payload)
    {
        var start = new ProcessStartInfo(python)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add(runner);
        start.ArgumentList.Add(script);
        start.ArgumentList.Add(payload);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start Python.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit(15_000);
        Assert.True(process.HasExited, "Python contract check did not finish.");
        Assert.True(process.ExitCode == 0, error);
        return System.Text.Json.JsonDocument.Parse(output);
    }

    private static string? FindPython()
    {
        foreach (var name in new[] { "python", "python3", "py" })
        {
            var path = Environment.GetEnvironmentVariable("PATH");
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            foreach (var directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                foreach (var extension in new[] { string.Empty, ".exe", ".cmd", ".bat" })
                {
                    var candidate = Path.Combine(directory, name + extension);
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }
            }
        }

        return null;
    }
}
