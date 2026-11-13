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
        Assert.DoesNotContain("args=payload.get", bridge, StringComparison.Ordinal);
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
