// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class CodexProtectionTests
{
    [Fact]
    public void Same_named_user_hook_is_not_owned_or_deleted()
    {
        using var temp = new TempTree();
        var codex = Path.Combine(temp.Root, ".codex");
        Directory.CreateDirectory(codex);
        var hooksPath = Path.Combine(codex, "hooks.json");
        File.WriteAllText(hooksPath, """
            {
              "mcp": { "keep": true },
              "hooks": {
                "PreToolUse": [
                  {
                    "hooks": [
                      {
                        "type": "command",
                        "command": "python /user-owned/axiom-codex-hook.py --dry-run"
                      }
                    ]
                  }
                ]
              }
            }
            """);
        CreateFakePython(temp.Root);

        var protection = new CodexProtection(temp.Root, temp.Root);
        Assert.True(protection.EnsureInstalled());

        var installed = File.ReadAllText(hooksPath);
        Assert.Contains("/user-owned/axiom-codex-hook.py", installed, StringComparison.Ordinal);
        using (var document = System.Text.Json.JsonDocument.Parse(installed))
        {
            var hooks = document.RootElement.GetProperty("hooks");
            foreach (var eventName in new[] { "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop" })
            {
                Assert.True(hooks.TryGetProperty(eventName, out var groups));
                Assert.Contains(
                    groups.EnumerateArray().SelectMany(group => group.GetProperty("hooks").EnumerateArray()),
                    handler =>
                        handler.TryGetProperty("command", out var command) &&
                        command.GetString()?.Contains("axiom-codex-hook.py", StringComparison.Ordinal) == true &&
                        handler.TryGetProperty("commandWindows", out var commandWindows) &&
                        commandWindows.GetString()?.EndsWith("--bridge-version 2", StringComparison.Ordinal) == true &&
                        handler.TryGetProperty("timeout", out var timeout) &&
                        timeout.GetInt32() == 30);
            }
        }

        protection.Remove();

        var remaining = File.ReadAllText(hooksPath);
        Assert.Contains("/user-owned/axiom-codex-hook.py", remaining, StringComparison.Ordinal);
        Assert.DoesNotContain("--bridge-version", remaining, StringComparison.Ordinal);
        Assert.Contains("\"keep\": true", remaining, StringComparison.Ordinal);
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
            Root = Path.Combine(Path.GetTempPath(), $"axiom-codex-{Guid.NewGuid():N}");
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
