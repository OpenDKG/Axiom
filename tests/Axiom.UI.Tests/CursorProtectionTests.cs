// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class CursorProtectionTests
{
    [Fact]
    public void Install_merges_preToolUse_and_preserves_user_hooks()
    {
        using var temp = new TempTree();
        var config = Path.Combine(temp.Root, ".cursor");
        Directory.CreateDirectory(config);
        var hooksPath = Path.Combine(config, "hooks.json");
        File.WriteAllText(hooksPath, """
            {
              "version": 1,
              "hooks": {
                "preToolUse": [
                  { "command": "./user-hook.ps1", "matcher": "Shell" }
                ]
              }
            }
            """);
        CreateFakePython(temp.Root);

        var protection = new CursorProtection(temp.Root, temp.Root);
        Assert.True(protection.IsCursorDetected);
        Assert.True(protection.EnsureInstalled());
        Assert.True(protection.IsInstalled);

        var installed = File.ReadAllText(hooksPath);
        Assert.Contains("user-hook.ps1", installed, StringComparison.Ordinal);
        Assert.Contains("axiom-cursor-hook.py", installed, StringComparison.Ordinal);
        Assert.NotEmpty(Directory.GetFiles(config, "hooks.json.axiom-backup-*"));

        Assert.True(protection.EnsureInstalled());
        Assert.Equal(1, CountOccurrences(File.ReadAllText(hooksPath), "axiom-cursor-hook.py"));
    }

    [Fact]
    public void Remove_deletes_only_the_managed_hook()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".cursor"));
        var hooksPath = Path.Combine(temp.Root, ".cursor", "hooks.json");
        File.WriteAllText(hooksPath, """
            {
              "version": 1,
              "hooks": {
                "preToolUse": [
                  { "command": "./user-hook.ps1", "matcher": "Shell" }
                ]
              }
            }
            """);
        CreateFakePython(temp.Root);

        var protection = new CursorProtection(temp.Root, temp.Root);
        Assert.True(protection.EnsureInstalled());
        protection.Remove();

        var remaining = File.ReadAllText(hooksPath);
        Assert.Contains("user-hook.ps1", remaining, StringComparison.Ordinal);
        Assert.DoesNotContain("axiom-cursor-hook.py", remaining, StringComparison.Ordinal);
        Assert.False(File.Exists(protection.HookScriptPath));
    }

    [Fact]
    public void Unsupported_or_non_object_config_is_not_overwritten()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".cursor"));
        var hooksPath = Path.Combine(temp.Root, ".cursor", "hooks.json");
        CreateFakePython(temp.Root);
        var protection = new CursorProtection(temp.Root, temp.Root);

        File.WriteAllText(hooksPath, """[{"user":true}]""");
        Assert.False(protection.EnsureInstalled());
        Assert.Equal("""[{"user":true}]""", File.ReadAllText(hooksPath));

        File.WriteAllText(hooksPath, """{"version":2,"hooks":{}}""");
        Assert.False(protection.EnsureInstalled());
        Assert.Equal("""{"version":2,"hooks":{}}""", File.ReadAllText(hooksPath));

        File.WriteAllText(hooksPath, """{"version":1.5,"hooks":{}}""");
        Assert.False(protection.EnsureInstalled());
        Assert.Equal("""{"version":1.5,"hooks":{}}""", File.ReadAllText(hooksPath));
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

    private static int CountOccurrences(string value, string needle)
    {
        var count = 0;
        var index = 0;
        while ((index = value.IndexOf(needle, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += needle.Length;
        }

        return count;
    }

    private sealed class TempTree : IDisposable
    {
        public TempTree()
        {
            Root = Path.Combine(Path.GetTempPath(), $"axiom-cursor-{Guid.NewGuid():N}");
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
