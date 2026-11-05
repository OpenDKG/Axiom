// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Netpetra.UI.Services;
using Xunit;

namespace Netpetra.UI.Tests;

public sealed class GeminiProtectionTests
{
    [Fact]
    public void Install_merges_BeforeTool_and_preserves_user_hooks()
    {
        using var temp = new TempTree();
        var config = Path.Combine(temp.Root, ".gemini");
        Directory.CreateDirectory(config);
        var settings = Path.Combine(config, "settings.json");
        File.WriteAllText(settings, """
            {
              "existing": true,
              "hooks": {
                "BeforeTool": [
                  {
                    "matcher": "read_file",
                    "hooks": [
                      { "type": "command", "command": "user-hook.ps1" }
                    ]
                  }
                ]
              }
            }
            """);
        CreateFakePython(temp.Root);

        var protection = new GeminiProtection(temp.Root, temp.Root);
        Assert.True(protection.IsGeminiDetected);
        Assert.True(protection.EnsureInstalled());
        Assert.True(protection.IsInstalled);

        var installed = File.ReadAllText(settings);
        Assert.Contains("user-hook.ps1", installed, StringComparison.Ordinal);
        Assert.Contains("netpetra-gemini-hook.py", installed, StringComparison.Ordinal);
        Assert.Contains("\"existing\": true", installed, StringComparison.Ordinal);
        Assert.True(File.Exists(protection.HookScriptPath));
        Assert.NotEmpty(Directory.GetFiles(config, "settings.json.netpetra-backup-*"));
    }

    [Fact]
    public void Remove_deletes_only_the_managed_hook()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".gemini"));
        var settings = Path.Combine(temp.Root, ".gemini", "settings.json");
        File.WriteAllText(settings, """
            {
              "hooks": {
                "BeforeTool": [
                  {
                    "matcher": "read_file",
                    "hooks": [
                      { "type": "command", "command": "user-hook.ps1" }
                    ]
                  }
                ]
              }
            }
            """);
        CreateFakePython(temp.Root);

        var protection = new GeminiProtection(temp.Root, temp.Root);
        Assert.True(protection.EnsureInstalled());
        protection.Remove();

        var remaining = File.ReadAllText(settings);
        Assert.Contains("user-hook.ps1", remaining, StringComparison.Ordinal);
        Assert.DoesNotContain("netpetra-gemini-hook.py", remaining, StringComparison.Ordinal);
        Assert.False(File.Exists(protection.HookScriptPath));
    }

    [Fact]
    public void Non_object_settings_is_not_overwritten()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".gemini"));
        var settings = Path.Combine(temp.Root, ".gemini", "settings.json");
        File.WriteAllText(settings, """[{"user":true}]""");
        CreateFakePython(temp.Root);

        var protection = new GeminiProtection(temp.Root, temp.Root);
        Assert.False(protection.EnsureInstalled());
        Assert.Equal("""[{"user":true}]""", File.ReadAllText(settings));
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

    private sealed class TempTree : IDisposable
    {
        public TempTree()
        {
            Root = Path.Combine(Path.GetTempPath(), $"netpetra-gemini-{Guid.NewGuid():N}");
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
