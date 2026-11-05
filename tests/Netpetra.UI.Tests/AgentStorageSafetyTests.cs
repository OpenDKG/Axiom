// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using Netpetra.UI.Services;
using Xunit;

namespace Netpetra.UI.Tests;

public sealed class AgentStorageSafetyTests
{
    [Fact]
    public void Detection_and_status_checks_do_not_create_agent_files()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".config", "opencode"));
        Directory.CreateDirectory(Path.Combine(temp.Root, ".codex"));

        var openCode = new OpenCodeProtection(temp.Root, temp.Root, temp.Root);
        var codex = new CodexProtection(temp.Root, temp.Root);

        Assert.True(openCode.IsOpenCodeDetected);
        Assert.False(openCode.IsInstalled);
        Assert.True(codex.IsCodexDetected);
        Assert.False(codex.IsInstalled);

        Assert.False(Directory.Exists(Path.Combine(temp.Root, ".config", "opencode", "plugins")));
        Assert.False(File.Exists(Path.Combine(temp.Root, ".codex", "hooks.json")));
        Assert.False(File.Exists(Path.Combine(
            temp.Root,
            "Netpetra",
            "modules",
            "blackbox",
            "agent-blackbox",
            "netpetra-guard-bridge.py")));
    }

    [Fact]
    public void Hook_installation_needs_python_and_does_not_write_without_it()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".config", "opencode"));
        Directory.CreateDirectory(Path.Combine(temp.Root, ".codex"));

        var openCode = new OpenCodeProtection(temp.Root, temp.Root, temp.Root);
        var codex = new CodexProtection(temp.Root, temp.Root);

        Assert.False(openCode.EnsureInstalled());
        Assert.False(codex.EnsureInstalled());
        Assert.False(Directory.Exists(Path.Combine(temp.Root, ".config", "opencode", "plugins")));
        Assert.False(File.Exists(Path.Combine(temp.Root, ".codex", "hooks.json")));
    }

    [Fact]
    public void Approved_plugin_write_backs_up_an_existing_managed_plugin()
    {
        using var temp = new TempTree();
        var pluginDirectory = Path.Combine(
            temp.Root,
            ".config",
            "opencode",
            "plugins",
            "netpetra-blackbox");
        Directory.CreateDirectory(pluginDirectory);
        var plugin = Path.Combine(pluginDirectory, "index.ts");
        File.WriteAllText(plugin, "// Managed by Netpetra. old version\n");

        var python = Path.Combine(
            temp.Root,
            "Netpetra",
            "modules",
            "blackbox",
            "agent-blackbox",
            "venv",
            "Scripts",
            "python.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(python)!);
        File.WriteAllText(python, string.Empty);

        var openCode = new OpenCodeProtection(temp.Root, temp.Root, temp.Root);
        Assert.True(openCode.EnsureInstalled());

        Assert.True(File.ReadAllText(plugin).Contains("Plugin.define", StringComparison.Ordinal));
        Assert.True(File.ReadAllText(plugin).Contains("ctx.tool.hook", StringComparison.Ordinal));
        Assert.True(File.Exists(openCode.V1PluginPath));
        Assert.Contains(
            "startsWith(\"2.\")",
            File.ReadAllText(openCode.V1PluginPath),
            StringComparison.Ordinal);
        Assert.True(openCode.IsInstalled);
        Assert.NotEmpty(Directory.GetFiles(pluginDirectory, "index.ts.netpetra-backup-*"));
    }

    [Fact]
    public async Task OpenCode_v2_plugin_registers_and_runs_the_guard_hook()
    {
        if (!IsNodeAvailable())
        {
            return;
        }

        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".config", "opencode"));
        var python = Path.Combine(
            temp.Root,
            "Netpetra",
            "modules",
            "blackbox",
            "agent-blackbox",
            "venv",
            "Scripts",
            "python.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(python)!);
        File.WriteAllText(python, string.Empty);

        var protection = new OpenCodeProtection(temp.Root, temp.Root, temp.Root);
        Assert.True(protection.EnsureInstalled());

        var probe = new AgentHookProbe(temp.Root, temp.Root);
        var result = await probe.TestAsync("opencode", CancellationToken.None);

        Assert.Equal("HOOK RAN", result.Status);
    }

    private static bool IsNodeAvailable()
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("node", "--version")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (process is null)
            {
                return false;
            }

            process.WaitForExit(3000);
            return process.HasExited && process.ExitCode == 0;
        }
        catch (Exception exception) when (exception is
            System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return false;
        }
    }

    [Fact]
    public void Old_flat_v1_plugin_is_not_reported_as_installed()
    {
        using var temp = new TempTree();
        var pluginDirectory = Path.Combine(temp.Root, ".config", "opencode", "plugins");
        Directory.CreateDirectory(pluginDirectory);
        File.WriteAllText(
            Path.Combine(pluginDirectory, "netpetra-blackbox.ts"),
            "// Managed by Netpetra. old V1 file\n");

        var python = Path.Combine(
            temp.Root,
            "Netpetra",
            "modules",
            "blackbox",
            "agent-blackbox",
            "venv",
            "Scripts",
            "python.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(python)!);
        File.WriteAllText(python, string.Empty);

        var openCode = new OpenCodeProtection(temp.Root, temp.Root, temp.Root);
        Assert.False(openCode.IsInstalled);
        Assert.True(openCode.EnsureInstalled());
        Assert.True(openCode.IsInstalled);
        Assert.True(File.Exists(openCode.PluginPath));
        Assert.Contains("Plugin.define", File.ReadAllText(openCode.PluginPath), StringComparison.Ordinal);
    }

    [Fact]
    public void Codex_install_does_not_modify_toml_config()
    {
        using var temp = new TempTree();
        var codexDirectory = Path.Combine(temp.Root, ".codex");
        Directory.CreateDirectory(codexDirectory);
        var config = Path.Combine(codexDirectory, "config.toml");
        const string userConfig = """
            # user-owned Codex configuration
            model = "user-model"
            approval_policy = "on-request"
            """;
        File.WriteAllText(config, userConfig);

        var python = Path.Combine(
            temp.Root,
            "Netpetra",
            "modules",
            "blackbox",
            "agent-blackbox",
            "venv",
            "Scripts",
            "python.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(python)!);
        File.WriteAllText(python, string.Empty);

        var codex = new CodexProtection(temp.Root, temp.Root);
        Assert.True(codex.EnsureInstalled());
        Assert.Equal(userConfig, File.ReadAllText(config));
    }

    [Fact]
    public void Codex_remove_without_managed_hook_leaves_user_file_unchanged()
    {
        using var temp = new TempTree();
        var codexDirectory = Path.Combine(temp.Root, ".codex");
        Directory.CreateDirectory(codexDirectory);
        var hooks = Path.Combine(codexDirectory, "hooks.json");
        const string userHooks = """
            {
              "hooks": {
                "PreToolUse": [
                  {
                    "matcher": ".*",
                    "hooks": [
                      { "type": "command", "command": "user-hook.ps1" }
                    ]
                  }
                ]
              }
            }
            """;
        File.WriteAllText(hooks, userHooks);

        var codex = new CodexProtection(temp.Root, temp.Root);
        codex.Remove();

        Assert.Equal(userHooks, File.ReadAllText(hooks));
    }

    [Fact]
    public void Codex_merge_preserves_unrelated_user_hooks()
    {
        using var temp = new TempTree();
        var codexDirectory = Path.Combine(temp.Root, ".codex");
        Directory.CreateDirectory(codexDirectory);
        var hooks = Path.Combine(codexDirectory, "hooks.json");
        File.WriteAllText(hooks, """
            {
              "hooks": {
                "PreToolUse": [
                  {
                    "matcher": ".*",
                    "hooks": [
                      { "type": "command", "command": "user-hook.ps1" }
                    ]
                  }
                ]
              }
            }
            """);

        var python = Path.Combine(
            temp.Root,
            "Netpetra",
            "modules",
            "blackbox",
            "agent-blackbox",
            "venv",
            "Scripts",
            "python.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(python)!);
        File.WriteAllText(python, string.Empty);

        var codex = new CodexProtection(temp.Root, temp.Root);
        Assert.True(codex.EnsureInstalled());

        var merged = File.ReadAllText(hooks);
        Assert.Contains("user-hook.ps1", merged, StringComparison.Ordinal);
        Assert.Contains("netpetra-codex-hook.py", merged, StringComparison.Ordinal);
    }

    [Fact]
    public void Reparse_point_helper_returns_false_for_a_normal_file()
    {
        using var temp = new TempTree();
        var file = Path.Combine(temp.Root, "normal.txt");
        File.WriteAllText(file, "test");
        Assert.False(StorageSafety.IsReparsePoint(file));
    }

    [Fact]
    public void Reparse_point_in_path_returns_false_for_a_normal_tree()
    {
        using var temp = new TempTree();
        var file = Path.Combine(temp.Root, "normal", "nested", "file.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, "test");
        Assert.False(StorageSafety.IsReparsePointInPath(file));
        Assert.False(StorageSafety.IsReparsePointInPath(
            Path.Combine(temp.Root, "missing", "file.txt")));
    }

    private sealed class TempTree : IDisposable
    {
        public TempTree()
        {
            Root = Path.Combine(Path.GetTempPath(), $"netpetra-ui-test-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Root, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
