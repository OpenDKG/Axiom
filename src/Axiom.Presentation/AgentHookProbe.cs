// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Axiom.Presentation;

public sealed record AgentHookTestResult(string Status, string Detail);

/// <summary>
/// Runs the installed hook adapter with a benign simulated tool call. This verifies that the hook
/// entrypoint can start and reach the local guard; it does not claim that a specific agent process
/// loaded the hook or that a real tool call was blocked.
/// </summary>
public sealed class AgentHookProbe
{
    private readonly string _userProfile;

    private readonly string _localAppData;

    public AgentHookProbe(string? userProfile = null, string? localAppData = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    public async Task<AgentHookTestResult> TestAsync(string kind, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(40));
        var token = timeout.Token;

        try
        {
            return kind.ToLowerInvariant() switch
            {
                "codex" => await TestCodexAsync(token).ConfigureAwait(false),
                "claude" => await TestClaudeAsync(token).ConfigureAwait(false),
                "antigravity" => await TestAntigravityAsync(token).ConfigureAwait(false),
                "cursor" => await TestCursorAsync(token).ConfigureAwait(false),
                "copilot" => await TestCopilotAsync(token).ConfigureAwait(false),
                "gemini" => await TestGeminiAsync(token).ConfigureAwait(false),
                "windsurf" => await TestWindsurfAsync(token).ConfigureAwait(false),
                "cline" => await TestClineAsync(token).ConfigureAwait(false),
                "zcode" => await TestLifecycleScriptAsync("ZCode", "axiom-zcode-hook.py", token).ConfigureAwait(false),
                "deepseek" => await TestLifecycleScriptAsync("DeepSeek Harness", "axiom-deepseek-hook.py", token).ConfigureAwait(false),
                "opencode" => await TestOpenCodeAsync("OpenCode", token).ConfigureAwait(false),
                "openchamber" => await TestOpenCodeAsync("OpenChamber", token).ConfigureAwait(false),
                _ => new AgentHookTestResult(
                    "SKIPPED",
                    "Axiom has no hook adapter for this recognized harness."),
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            Win32Exception or InvalidOperationException or JsonException or OperationCanceledException)
        {
            return new AgentHookTestResult("FAIL", "Hook test could not run: " + exception.Message);
        }
    }

    private static async Task<(int ExitCode, string Output, string Error)> RunProcessAsync(
        ProcessStartInfo startInfo,
        string startFailureMessage,
        string? stdinPayload,
        CancellationToken cancellationToken)
    {
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException(startFailureMessage);

        if (stdinPayload is not null)
        {
            await process.StandardInput.WriteAsync(stdinPayload.AsMemory(), cancellationToken).ConfigureAwait(false);
            process.StandardInput.Close();
        }

        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            var output = await outputTask.ConfigureAwait(false);
            var error = await errorTask.ConfigureAwait(false);
            return (process.ExitCode, output, error);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception exception) when (exception is InvalidOperationException or Win32Exception)
            {
            }

            ObserveFaults(outputTask);
            ObserveFaults(errorTask);
            try
            {
                await Task.WhenAny(Task.WhenAll(outputTask, errorTask), Task.Delay(500, CancellationToken.None))
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is OperationCanceledException or IOException or InvalidOperationException)
            {
            }

            throw;
        }
    }

    private static void ObserveFaults(Task task) =>
        _ = task.ContinueWith(
            static completed => _ = completed.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);

    private static bool IsManagedScript(string path)
    {
        try
        {
            return File.Exists(path) &&
                   File.ReadAllText(path).Contains("Managed by Axiom", StringComparison.Ordinal);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private async Task<AgentHookTestResult> TestCodexAsync(CancellationToken cancellationToken)
    {
        var root = Path.Combine(_localAppData, "Axiom", "modules", "blackbox", "agent-blackbox");
        var python = AgentPlatform.VenvPython(root);
        var hook = Path.Combine(root, "axiom-codex-hook.py");
        if (!File.Exists(python) || !IsManagedScript(hook))
        {
            return new AgentHookTestResult("FAIL", "Codex hook or Blackbox Python runtime is missing.");
        }

        var startInfo = new ProcessStartInfo(python)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = root,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add(hook);

        var (exitCode, output, _) = await RunProcessAsync(
            startInfo,
            "Could not start the Codex hook.",
            JsonSerializer.Serialize(new
            {
                tool_name = "read",
                tool_input = new { path = Path.Combine(Path.GetTempPath(), "axiom-hook-test.txt") },
                session_id = "axiom-hook-test",
                tool_use_id = Guid.NewGuid().ToString("N"),
            }),
            cancellationToken).ConfigureAwait(false);

        if (exitCode != 0)
        {
            return new AgentHookTestResult("FAIL", $"Codex hook exited with {exitCode}.");
        }

        if (IsDeniedCodexOutput(output))
        {
            return new AgentHookTestResult(
                "BLOCKED",
                "Codex hook executed and returned permissionDecision: deny for the benign test call. " +
                "The real Codex process was not exercised.");
        }

        return new AgentHookTestResult(
            "HOOK RAN",
            "Codex hook executed and reached the local guard without a block. The real Codex process was not exercised.");
    }

    private static bool IsDeniedCodexOutput(string output)
    {
        try
        {
            using var document = JsonDocument.Parse(output);
            var root = document.RootElement;
            if (root.TryGetProperty("decision", out var legacy) &&
                string.Equals(legacy.GetString(), "block", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return root.TryGetProperty("hookSpecificOutput", out var hook) &&
                   hook.TryGetProperty("permissionDecision", out var decision) &&
                   string.Equals(decision.GetString(), "deny", StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private async Task<AgentHookTestResult> TestClaudeAsync(CancellationToken cancellationToken)
    {
        var root = Path.Combine(_localAppData, "Axiom", "modules", "blackbox", "agent-blackbox");
        var python = AgentPlatform.VenvPython(root);
        var hook = Path.Combine(root, "axiom-claude-hook.py");
        if (!File.Exists(python) || !IsManagedScript(hook))
        {
            return new AgentHookTestResult("FAIL", "Claude Code hook or Blackbox Python runtime is missing.");
        }

        var startInfo = new ProcessStartInfo(python)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = root,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add(hook);

        var (exitCode, output, _) = await RunProcessAsync(
            startInfo,
            "Could not start the Claude Code hook.",
            JsonSerializer.Serialize(new
            {
                tool_name = "Read",
                tool_input = new { path = Path.Combine(Path.GetTempPath(), "axiom-hook-test.txt") },
                session_id = "axiom-hook-test",
                tool_use_id = Guid.NewGuid().ToString("N"),
            }),
            cancellationToken).ConfigureAwait(false);

        if (exitCode != 0)
        {
            return new AgentHookTestResult("FAIL", $"Claude Code hook exited with {exitCode}.");
        }

        if (IsDeniedCodexOutput(output))
        {
            return new AgentHookTestResult(
                "BLOCKED",
                "Claude Code hook executed and returned permissionDecision: deny for the benign test call. " +
                "The real Claude Code process was not exercised.");
        }

        return new AgentHookTestResult(
            "HOOK RAN",
            "Claude Code hook executed and reached the local guard without a block. The real Claude Code process was not exercised.");
    }

    private async Task<AgentHookTestResult> TestCursorAsync(CancellationToken cancellationToken)
    {
        var root = Path.Combine(_localAppData, "Axiom", "modules", "blackbox", "agent-blackbox");
        var python = AgentPlatform.VenvPython(root);
        var hook = Path.Combine(root, "axiom-cursor-hook.py");
        if (!File.Exists(python) || !IsManagedScript(hook))
        {
            return new AgentHookTestResult("FAIL", "Cursor hook or Blackbox Python runtime is missing.");
        }

        var startInfo = new ProcessStartInfo(python)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = root,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add(hook);

        var (exitCode, output, _) = await RunProcessAsync(
            startInfo,
            "Could not start the Cursor hook.",
            JsonSerializer.Serialize(new
            {
                tool_name = "Read",
                tool_input = new { path = Path.Combine(Path.GetTempPath(), "axiom-hook-test.txt") },
                conversation_id = "axiom-hook-test",
                tool_use_id = Guid.NewGuid().ToString("N"),
            }),
            cancellationToken).ConfigureAwait(false);

        if (exitCode != 0)
        {
            return new AgentHookTestResult("FAIL", $"Cursor hook exited with {exitCode}.");
        }

        if (IsDeniedCursorOutput(output))
        {
            return new AgentHookTestResult(
                "BLOCKED",
                "Cursor hook executed and returned permission: deny for the benign test call. " +
                "The real Cursor process was not exercised.");
        }

        return new AgentHookTestResult(
            "HOOK RAN",
            "Cursor hook executed and reached the local guard without a block. The real Cursor process was not exercised.");
    }

    private static bool IsDeniedCursorOutput(string output)
    {
        try
        {
            using var document = JsonDocument.Parse(output);
            return document.RootElement.TryGetProperty("permission", out var permission) &&
                   string.Equals(permission.GetString(), "deny", StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private async Task<AgentHookTestResult> TestCopilotAsync(CancellationToken cancellationToken)
    {
        var root = Path.Combine(_localAppData, "Axiom", "modules", "blackbox", "agent-blackbox");
        var python = AgentPlatform.VenvPython(root);
        var hook = Path.Combine(root, "axiom-copilot-hook.py");
        if (!File.Exists(python) || !IsManagedScript(hook))
        {
            return new AgentHookTestResult("FAIL", "Copilot hook or Blackbox Python runtime is missing.");
        }

        var startInfo = new ProcessStartInfo(python)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = root,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add(hook);

        var (exitCode, output, _) = await RunProcessAsync(
            startInfo,
            "Could not start the Copilot hook.",
            JsonSerializer.Serialize(new
            {
                toolName = "read",
                toolArgs = new { path = Path.Combine(Path.GetTempPath(), "axiom-hook-test.txt") },
                sessionId = "axiom-hook-test",
                toolCallId = Guid.NewGuid().ToString("N"),
            }),
            cancellationToken).ConfigureAwait(false);

        if (exitCode != 0)
        {
            return new AgentHookTestResult("FAIL", $"Copilot hook exited with {exitCode}.");
        }

        if (IsDeniedCopilotOutput(output))
        {
            return new AgentHookTestResult(
                "BLOCKED",
                "Copilot hook executed and returned permissionDecision: deny for the benign test call. " +
                "The real Copilot CLI process was not exercised.");
        }

        return new AgentHookTestResult(
            "HOOK RAN",
            "Copilot hook executed and reached the local guard without a block. The real Copilot CLI process was not exercised.");
    }

    private static bool IsDeniedCopilotOutput(string output)
    {
        try
        {
            using var document = JsonDocument.Parse(output);
            return document.RootElement.TryGetProperty("permissionDecision", out var decision) &&
                   string.Equals(decision.GetString(), "deny", StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private async Task<AgentHookTestResult> TestGeminiAsync(CancellationToken cancellationToken)
    {
        var root = Path.Combine(_localAppData, "Axiom", "modules", "blackbox", "agent-blackbox");
        var python = AgentPlatform.VenvPython(root);
        var hook = Path.Combine(root, "axiom-gemini-hook.py");
        if (!File.Exists(python) || !IsManagedScript(hook))
        {
            return new AgentHookTestResult("FAIL", "Gemini hook or Blackbox Python runtime is missing.");
        }

        var startInfo = new ProcessStartInfo(python)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = root,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add(hook);

        var (exitCode, output, _) = await RunProcessAsync(
            startInfo,
            "Could not start the Gemini hook.",
            JsonSerializer.Serialize(new
            {
                tool_name = "read_file",
                tool_input = new { path = Path.Combine(Path.GetTempPath(), "axiom-hook-test.txt") },
                session_id = "axiom-hook-test",
            }),
            cancellationToken).ConfigureAwait(false);

        if (exitCode != 0)
        {
            return new AgentHookTestResult("FAIL", $"Gemini hook exited with {exitCode}.");
        }

        if (IsDeniedGeminiOutput(output))
        {
            return new AgentHookTestResult(
                "BLOCKED",
                "Gemini hook executed and returned decision: deny for the benign test call. " +
                "The real Gemini CLI process was not exercised.");
        }

        return new AgentHookTestResult(
            "HOOK RAN",
            "Gemini hook executed and reached the local guard without a block. The real Gemini CLI process was not exercised.");
    }

    private async Task<AgentHookTestResult> TestAntigravityAsync(CancellationToken cancellationToken)
    {
        var root = Path.Combine(_localAppData, "Axiom", "modules", "blackbox", "agent-blackbox");
        var python = Path.Combine(root, "venv", "Scripts", "python.exe");
        var hook = Path.Combine(root, "axiom-antigravity-hook.py");
        if (!File.Exists(python) || !IsManagedScript(hook))
        {
            return new AgentHookTestResult("FAIL", "Antigravity hook or Blackbox Python runtime is missing.");
        }

        var startInfo = new ProcessStartInfo(python)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = root,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add(hook);

        var (exitCode, output, _) = await RunProcessAsync(
            startInfo,
            "Could not start the Antigravity hook.",
            JsonSerializer.Serialize(new
            {
                toolCall = new
                {
                    name = "read_file",
                    args = new { Path = Path.Combine(Path.GetTempPath(), "axiom-hook-test.txt") },
                },
                conversationId = "axiom-hook-test",
                stepIdx = 1,
            }),
            cancellationToken).ConfigureAwait(false);

        if (exitCode != 0)
        {
            return new AgentHookTestResult("FAIL", $"Antigravity hook exited with {exitCode}.");
        }

        if (IsDeniedGeminiOutput(output))
        {
            return new AgentHookTestResult(
                "BLOCKED",
                "Antigravity hook executed and returned decision: deny for the benign test call. " +
                "The real Antigravity process was not exercised.");
        }

        return new AgentHookTestResult(
            "HOOK RAN",
            "Antigravity hook executed and reached the local guard without a block. The real Antigravity process was not exercised.");
    }

    private static bool IsDeniedGeminiOutput(string output)
    {
        try
        {
            using var document = JsonDocument.Parse(output);
            return document.RootElement.TryGetProperty("decision", out var decision) &&
                   string.Equals(decision.GetString(), "deny", StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private async Task<AgentHookTestResult> TestWindsurfAsync(CancellationToken cancellationToken)
    {
        var root = Path.Combine(_localAppData, "Axiom", "modules", "blackbox", "agent-blackbox");
        var python = AgentPlatform.VenvPython(root);
        var hook = Path.Combine(root, "axiom-windsurf-hook.py");
        if (!File.Exists(python) || !IsManagedScript(hook))
        {
            return new AgentHookTestResult("FAIL", "Windsurf hook or Blackbox Python runtime is missing.");
        }

        var startInfo = new ProcessStartInfo(python)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = root,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add(hook);

        var (exitCode, _, error) = await RunProcessAsync(
            startInfo,
            "Could not start the Windsurf hook.",
            JsonSerializer.Serialize(new
            {
                agent_action_name = "pre_run_command",
                trajectory_id = "axiom-hook-test",
                execution_id = Guid.NewGuid().ToString("N"),
                tool_info = new
                {
                    command_line = "read axiom-hook-test.txt",
                    cwd = Path.GetTempPath(),
                },
            }),
            cancellationToken).ConfigureAwait(false);

        if (exitCode == 2)
        {
            return new AgentHookTestResult(
                "BLOCKED",
                "Windsurf hook executed and returned exit code 2 for the benign test call. " +
                (string.IsNullOrWhiteSpace(error) ? string.Empty : error.Trim() + " ") +
                "The real Cascade process was not exercised.");
        }

        if (exitCode == 0)
        {
            return new AgentHookTestResult(
                "HOOK RAN",
                "Windsurf hook executed and reached the local guard without a block. The real Cascade process was not exercised.");
        }

        return new AgentHookTestResult("FAIL", $"Windsurf hook exited with {exitCode}.");
    }

    private async Task<AgentHookTestResult> TestClineAsync(CancellationToken cancellationToken)
    {
        var root = Path.Combine(_localAppData, "Axiom", "modules", "blackbox", "agent-blackbox");
        var python = AgentPlatform.VenvPython(root);
        var hook = Path.Combine(_userProfile, "Documents", "Cline", "Hooks", "PreToolUse.py");
        if (!File.Exists(python) || !IsManagedScript(hook))
        {
            return new AgentHookTestResult(
                "FAIL",
                "Cline hook is missing, not Axiom-managed, or the Blackbox Python runtime is missing.");
        }

        var startInfo = new ProcessStartInfo(python)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = root,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add(hook);

        var (exitCode, output, _) = await RunProcessAsync(
            startInfo,
            "Could not start the Cline hook.",
            JsonSerializer.Serialize(new
            {
                taskId = "axiom-hook-test",
                tool_call = new
                {
                    id = Guid.NewGuid().ToString("N"),
                    name = "read_files",
                    input = new { filePath = Path.Combine(Path.GetTempPath(), "axiom-hook-test.txt") },
                },
            }),
            cancellationToken).ConfigureAwait(false);

        if (exitCode != 0)
        {
            return new AgentHookTestResult("FAIL", $"Cline hook exited with {exitCode}.");
        }

        if (IsCancelledClineOutput(output))
        {
            return new AgentHookTestResult(
                "BLOCKED",
                "Cline hook executed and returned cancel: true for the benign test call. " +
                "The real Cline process was not exercised.");
        }

        return new AgentHookTestResult(
            "HOOK RAN",
            "Cline hook executed and reached the local guard without a block. The real Cline process was not exercised.");
    }

    private static bool IsCancelledClineOutput(string output)
    {
        try
        {
            using var document = JsonDocument.Parse(output);
            return document.RootElement.TryGetProperty("cancel", out var cancel) &&
                   cancel.ValueKind == JsonValueKind.True;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private async Task<AgentHookTestResult> TestLifecycleScriptAsync(
        string label,
        string scriptName,
        CancellationToken cancellationToken)
    {
        var root = Path.Combine(_localAppData, "Axiom", "modules", "blackbox", "agent-blackbox");
        var python = AgentPlatform.VenvPython(root);
        var hook = Path.Combine(root, scriptName);
        if (!File.Exists(python) || !IsManagedScript(hook))
        {
            return new AgentHookTestResult("FAIL", $"{label} hook or Blackbox Python runtime is missing.");
        }

        var startInfo = new ProcessStartInfo(python)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = root,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add(hook);

        var (exitCode, output, _) = await RunProcessAsync(
            startInfo,
            $"Could not start the {label} hook.",
            JsonSerializer.Serialize(new
            {
                hook_event_name = "PreToolUse",
                tool_name = "Read",
                tool_input = new { path = Path.Combine(Path.GetTempPath(), "axiom-hook-test.txt") },
                session_id = "axiom-hook-test",
                tool_use_id = Guid.NewGuid().ToString("N"),
            }),
            cancellationToken).ConfigureAwait(false);

        if (exitCode != 0)
        {
            return new AgentHookTestResult("FAIL", $"{label} hook exited with {exitCode}.");
        }

        if (IsDeniedCodexOutput(output))
        {
            return new AgentHookTestResult(
                "BLOCKED",
                $"{label} hook executed and returned permissionDecision: deny for the benign test call. " +
                "The real agent process was not exercised.");
        }

        return new AgentHookTestResult(
            "HOOK RAN",
            $"{label} hook executed and reached the local guard without a block. " +
            "The real agent process was not exercised.");
    }

    private async Task<AgentHookTestResult> TestOpenCodeAsync(string label, CancellationToken cancellationToken)
    {
        var root = Path.Combine(_localAppData, "Axiom", "modules", "blackbox", "agent-blackbox");
        var python = AgentPlatform.VenvPython(root);
        var plugin = Path.Combine(
            _userProfile,
            ".config",
            "opencode",
            "plugins",
            "axiom-blackbox",
            "index.ts");
        if (!File.Exists(python) || !IsManagedScript(plugin))
        {
            return new AgentHookTestResult(
                "FAIL",
                $"{label} hook is missing, not Axiom-managed, or the Blackbox Python runtime is missing.");
        }

        var temp = Path.Combine(Path.GetTempPath(), "axiom-hook-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var shimDirectory = Path.Combine(temp, "node_modules", "@opencode", "plugin");
            Directory.CreateDirectory(shimDirectory);
            await File.WriteAllTextAsync(
                Path.Combine(shimDirectory, "package.json"),
                """{"name":"@opencode/plugin","type":"module","exports":{".":"./index.js"}}""",
                cancellationToken).ConfigureAwait(false);
            await File.WriteAllTextAsync(
                Path.Combine(shimDirectory, "index.js"),
                "export const Plugin = { define: (definition) => definition };\n",
                cancellationToken).ConfigureAwait(false);

            var pluginCopy = Path.Combine(temp, "plugin.mjs");
            File.Copy(plugin, pluginCopy);
            var harness = Path.Combine(temp, "test.mjs");
            await File.WriteAllTextAsync(harness, """
                import { pathToFileURL } from "node:url"

                const [pluginPath, canary] = process.argv.slice(2)
                try {
                  const module = await import(pathToFileURL(pluginPath).href)
                  let handler
                  const context = {
                    tool: {
                      hook(name, callback) {
                        if (name === "execute.before") handler = callback
                      },
                    },
                  }
                  await module.default.setup(context)
                  if (!handler) {
                    console.log("NO_HOOK")
                    process.exit(3)
                  }
                  try {
                    await handler({
                      tool: "read",
                      input: { path: canary },
                      sessionID: "axiom-hook-test",
                      id: "test",
                    })
                    console.log("ALLOWED")
                  } catch (error) {
                    console.log("BLOCKED:" + (error?.message || "blocked"))
                  }
                } catch (error) {
                  console.log("ERROR:" + (error?.message || "unknown"))
                  process.exit(2)
                }
                """, cancellationToken).ConfigureAwait(false);

            var startInfo = new ProcessStartInfo("node")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = temp,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            startInfo.ArgumentList.Add(harness);
            startInfo.ArgumentList.Add(pluginCopy);
            startInfo.ArgumentList.Add(Path.Combine(Path.GetTempPath(), "axiom-hook-test.txt"));

            var (exitCode, output, error) = await RunProcessAsync(
                startInfo,
                "Could not start Node for the hook test.",
                stdinPayload: null,
                cancellationToken).ConfigureAwait(false);

            if (output.Contains("BLOCKED:", StringComparison.Ordinal))
            {
                return new AgentHookTestResult(
                    "BLOCKED",
                    $"{label} hook executed and blocked the benign test call. The real agent process was not exercised.");
            }

            if (exitCode == 0 && output.Contains("ALLOWED", StringComparison.Ordinal))
            {
                return new AgentHookTestResult(
                    "HOOK RAN",
                    $"{label} hook executed and reached the local guard without a block. The real agent process was not exercised.");
            }

            return new AgentHookTestResult(
                "FAIL",
                $"{label} hook test did not complete (exit {exitCode})." +
                (string.IsNullOrWhiteSpace(error) ? string.Empty : " " + error.Trim()));
        }
        finally
        {
            try
            {
                Directory.Delete(temp, recursive: true);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }
    }
}
