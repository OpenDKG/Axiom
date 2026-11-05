// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Netpetra.UI.Services;

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
        try
        {
            return kind.ToLowerInvariant() switch
            {
                "codex" => await TestCodexAsync(cancellationToken).ConfigureAwait(false),
                "claude" => await TestClaudeAsync(cancellationToken).ConfigureAwait(false),
                "opencode" => await TestOpenCodeAsync("OpenCode", cancellationToken).ConfigureAwait(false),
                "openchamber" => await TestOpenCodeAsync("OpenChamber", cancellationToken).ConfigureAwait(false),
                _ => new AgentHookTestResult(
                    "SKIPPED",
                    "Netpetra has no hook adapter for this recognized harness."),
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            Win32Exception or InvalidOperationException or JsonException or TaskCanceledException)
        {
            return new AgentHookTestResult("FAIL", "Hook test could not run: " + exception.Message);
        }
    }

    private async Task<AgentHookTestResult> TestCodexAsync(CancellationToken cancellationToken)
    {
        var root = Path.Combine(_localAppData, "Netpetra", "modules", "blackbox", "agent-blackbox");
        var python = Path.Combine(root, "venv", "Scripts", "python.exe");
        var hook = Path.Combine(root, "netpetra-codex-hook.py");
        if (!File.Exists(python) || !File.Exists(hook))
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

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start the Codex hook.");
        await process.StandardInput.WriteAsync(JsonSerializer.Serialize(new
        {
            tool_name = "read",
            tool_input = new { path = Path.Combine(Path.GetTempPath(), "netpetra-hook-test.txt") },
            session_id = "netpetra-hook-test",
            tool_use_id = Guid.NewGuid().ToString("N"),
        })).ConfigureAwait(false);
        process.StandardInput.Close();

        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        var output = await outputTask.ConfigureAwait(false);
        _ = await errorTask.ConfigureAwait(false);

        if (process.ExitCode != 0)
        {
            return new AgentHookTestResult("FAIL", $"Codex hook exited with {process.ExitCode}.");
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
            return document.RootElement.TryGetProperty("hookSpecificOutput", out var hook) &&
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
        var root = Path.Combine(_localAppData, "Netpetra", "modules", "blackbox", "agent-blackbox");
        var python = Path.Combine(root, "venv", "Scripts", "python.exe");
        var hook = Path.Combine(root, "netpetra-claude-hook.py");
        if (!File.Exists(python) || !File.Exists(hook))
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

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start the Claude Code hook.");
        await process.StandardInput.WriteAsync(JsonSerializer.Serialize(new
        {
            tool_name = "Read",
            tool_input = new { path = Path.Combine(Path.GetTempPath(), "netpetra-hook-test.txt") },
            session_id = "netpetra-hook-test",
            tool_use_id = Guid.NewGuid().ToString("N"),
        })).ConfigureAwait(false);
        process.StandardInput.Close();

        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        var output = await outputTask.ConfigureAwait(false);
        _ = await errorTask.ConfigureAwait(false);

        if (process.ExitCode != 0)
        {
            return new AgentHookTestResult("FAIL", $"Claude Code hook exited with {process.ExitCode}.");
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

    private async Task<AgentHookTestResult> TestOpenCodeAsync(string label, CancellationToken cancellationToken)
    {
        var root = Path.Combine(_localAppData, "Netpetra", "modules", "blackbox", "agent-blackbox");
        var python = Path.Combine(root, "venv", "Scripts", "python.exe");
        var plugin = Path.Combine(
            _userProfile,
            ".config",
            "opencode",
            "plugins",
            "netpetra-blackbox",
            "index.ts");
        if (!File.Exists(python) || !File.Exists(plugin))
        {
            return new AgentHookTestResult("FAIL", $"{label} hook files or Blackbox Python runtime are missing.");
        }

        var temp = Path.Combine(Path.GetTempPath(), "netpetra-hook-test-" + Guid.NewGuid().ToString("N"));
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
                      sessionID: "netpetra-hook-test",
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
            startInfo.ArgumentList.Add(Path.Combine(Path.GetTempPath(), "netpetra-hook-test.txt"));

            using var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("Could not start Node for the hook test.");
            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

            if (output.Contains("BLOCKED:", StringComparison.Ordinal))
            {
                return new AgentHookTestResult(
                    "BLOCKED",
                    $"{label} hook executed and blocked the benign test call. The real agent process was not exercised.");
            }

            if (process.ExitCode == 0 && output.Contains("ALLOWED", StringComparison.Ordinal))
            {
                return new AgentHookTestResult(
                    "HOOK RAN",
                    $"{label} hook executed and reached the local guard without a block. The real agent process was not exercised.");
            }

            return new AgentHookTestResult(
                "FAIL",
                $"{label} hook test did not complete (exit {process.ExitCode}).");
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
