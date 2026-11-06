// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class WindsurfProtectionTests
{
    [Fact]
    public void Install_merges_three_pre_hooks_and_preserves_user_hooks()
    {
        using var temp = new TempTree();
        var config = Path.Combine(temp.Root, ".codeium", "windsurf");
        Directory.CreateDirectory(config);
        var hooksPath = Path.Combine(config, "hooks.json");
        File.WriteAllText(hooksPath, """
            {
              "hooks": {
                "pre_run_command": [
                  { "command": "user-hook.ps1", "show_output": true }
                ]
              }
            }
            """);
        CreateFakePython(temp.Root);

        var protection = new WindsurfProtection(temp.Root, temp.Root);
        Assert.True(protection.IsWindsurfDetected);
        Assert.True(protection.EnsureInstalled());
        Assert.True(protection.IsInstalled);

        var installed = File.ReadAllText(hooksPath);
        Assert.Contains("user-hook.ps1", installed, StringComparison.Ordinal);
        Assert.Contains("axiom-windsurf-hook.py", installed, StringComparison.Ordinal);
        Assert.Contains("pre_run_command", installed, StringComparison.Ordinal);
        Assert.Contains("pre_write_code", installed, StringComparison.Ordinal);
        Assert.Contains("pre_mcp_tool_use", installed, StringComparison.Ordinal);
        Assert.NotEmpty(Directory.GetFiles(config, "hooks.json.axiom-backup-*"));
    }

    [Fact]
    public void Remove_deletes_only_managed_hooks_and_keeps_user_hook()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".codeium", "windsurf"));
        var hooksPath = Path.Combine(temp.Root, ".codeium", "windsurf", "hooks.json");
        File.WriteAllText(hooksPath, """
            {
              "hooks": {
                "pre_run_command": [
                  { "command": "user-hook.ps1", "show_output": true }
                ]
              }
            }
            """);
        CreateFakePython(temp.Root);

        var protection = new WindsurfProtection(temp.Root, temp.Root);
        Assert.True(protection.EnsureInstalled());
        protection.Remove();

        var remaining = File.ReadAllText(hooksPath);
        Assert.Contains("user-hook.ps1", remaining, StringComparison.Ordinal);
        Assert.DoesNotContain("axiom-windsurf-hook.py", remaining, StringComparison.Ordinal);
        Assert.False(File.Exists(protection.HookScriptPath));
    }

    [Fact]
    public void Unsupported_config_shape_is_not_overwritten()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".codeium", "windsurf"));
        var hooksPath = Path.Combine(temp.Root, ".codeium", "windsurf", "hooks.json");
        CreateFakePython(temp.Root);
        var protection = new WindsurfProtection(temp.Root, temp.Root);

        File.WriteAllText(hooksPath, """{"hooks":[{"user":true}]}""");
        Assert.False(protection.EnsureInstalled());
        Assert.Equal("""{"hooks":[{"user":true}]}""", File.ReadAllText(hooksPath));
    }

    private static void CreateFakePython(string root)
    {
        var python = Path.Combine(
            root,
            "Axiom",
            "modules",
            "blackbox",
            "agent-blackbox",
            "venv",
            "Scripts",
            "python.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(python)!);
        File.WriteAllText(python, string.Empty);
    }

    private sealed class TempTree : IDisposable
    {
        public TempTree()
        {
            Root = Path.Combine(Path.GetTempPath(), $"axiom-windsurf-{Guid.NewGuid():N}");
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
