// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Netpetra.UI.Services;
using Xunit;

namespace Netpetra.UI.Tests;

public sealed class ClaudeProtectionTests
{
    [Fact]
    public void Install_merges_lifecycle_hooks_and_preserves_user_hooks()
    {
        using var temp = new TempTree();
        var config = Path.Combine(temp.Root, ".claude");
        Directory.CreateDirectory(config);
        var settings = Path.Combine(config, "settings.json");
        File.WriteAllText(settings, """
            {
              "existing": true,
              "hooks": {
                "PreToolUse": [
                  {
                    "matcher": "Bash",
                    "hooks": [
                      { "type": "command", "command": "user-hook.ps1" }
                    ]
                  }
                ]
              }
            }
            """);
        CreateFakePython(temp.Root);

        var protection = new ClaudeProtection(temp.Root, temp.Root);
        Assert.True(protection.IsClaudeDetected);
        Assert.True(protection.EnsureInstalled());
        Assert.True(protection.IsInstalled);

        var installed = File.ReadAllText(settings);
        Assert.Contains("user-hook.ps1", installed, StringComparison.Ordinal);
        Assert.Contains("netpetra-claude-hook.py", installed, StringComparison.Ordinal);
        Assert.Contains("\"existing\": true", installed, StringComparison.Ordinal);
        Assert.True(File.Exists(protection.HookScriptPath));
        Assert.NotEmpty(Directory.GetFiles(config, "settings.json.netpetra-backup-*"));

        Assert.True(protection.EnsureInstalled());
        var installedAgain = File.ReadAllText(settings);
        Assert.Equal(5, CountOccurrences(installedAgain, "netpetra-claude-hook.py"));
        using var document = System.Text.Json.JsonDocument.Parse(installedAgain);
        var hooks = document.RootElement.GetProperty("hooks");
        foreach (var eventName in new[] { "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop" })
        {
            Assert.True(hooks.TryGetProperty(eventName, out var groups));
            Assert.Contains(
                groups.EnumerateArray().SelectMany(group => group.GetProperty("hooks").EnumerateArray()),
                handler =>
                    handler.TryGetProperty("args", out var args) &&
                    args.GetArrayLength() > 0 &&
                    args[0].GetString()?.Contains("netpetra-claude-hook.py", StringComparison.Ordinal) == true &&
                    handler.TryGetProperty("timeout", out var timeout) &&
                    timeout.GetInt32() == 30);
        }
    }

    [Fact]
    public void Non_object_settings_file_is_never_overwritten()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".claude"));
        var settings = Path.Combine(temp.Root, ".claude", "settings.json");
        const string userJson = """[{"user":true}]""";
        File.WriteAllText(settings, userJson);
        CreateFakePython(temp.Root);

        var protection = new ClaudeProtection(temp.Root, temp.Root);
        Assert.False(protection.EnsureInstalled());
        Assert.Equal(userJson, File.ReadAllText(settings));
    }

    [Fact]
    public void Remove_deletes_only_the_managed_hook_and_keeps_user_hook()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".claude"));
        var settings = Path.Combine(temp.Root, ".claude", "settings.json");
        File.WriteAllText(settings, """
            {
              "hooks": {
                "PreToolUse": [
                  {
                    "matcher": "Bash",
                    "hooks": [
                      { "type": "command", "command": "user-hook.ps1" }
                    ]
                  }
                ]
              }
            }
            """);
        CreateFakePython(temp.Root);

        var protection = new ClaudeProtection(temp.Root, temp.Root);
        Assert.True(protection.EnsureInstalled());
        protection.Remove();

        var remaining = File.ReadAllText(settings);
        Assert.Contains("user-hook.ps1", remaining, StringComparison.Ordinal);
        Assert.DoesNotContain("netpetra-claude-hook.py", remaining, StringComparison.Ordinal);
        Assert.False(File.Exists(protection.HookScriptPath));
    }

    private static void CreateFakePython(string root)
    {
        var python = Path.Combine(
            root,
            "Netpetra",
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
            Root = Path.Combine(Path.GetTempPath(), $"netpetra-claude-{Guid.NewGuid():N}");
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
