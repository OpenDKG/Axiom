// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Netpetra.UI.Services;
using Xunit;

namespace Netpetra.UI.Tests;

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
                        "command": "python /user-owned/netpetra-codex-hook.py --dry-run"
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
        Assert.Contains("/user-owned/netpetra-codex-hook.py", installed, StringComparison.Ordinal);
        Assert.Equal(2, CountOccurrences(installed, "netpetra-codex-hook.py"));

        protection.Remove();

        var remaining = File.ReadAllText(hooksPath);
        Assert.Contains("/user-owned/netpetra-codex-hook.py", remaining, StringComparison.Ordinal);
        Assert.Equal(1, CountOccurrences(remaining, "netpetra-codex-hook.py"));
        Assert.Contains("\"keep\": true", remaining, StringComparison.Ordinal);
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
            Root = Path.Combine(Path.GetTempPath(), $"netpetra-codex-{Guid.NewGuid():N}");
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
