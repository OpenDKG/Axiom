// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class CopilotProtectionTests
{
    [Fact]
    public void Install_writes_a_axiom_owned_hook_file()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".copilot"));
        CreateFakePython(temp.Root);

        var protection = new CopilotProtection(temp.Root, temp.Root);
        Assert.True(protection.IsCopilotDetected);
        Assert.True(protection.EnsureInstalled());
        Assert.True(protection.IsInstalled);

        var hook = File.ReadAllText(protection.HooksPath);
        Assert.Contains("\"version\": 1", hook, StringComparison.Ordinal);
        Assert.Contains("preToolUse", hook, StringComparison.Ordinal);
        Assert.Contains("axiom-copilot-hook.py", hook, StringComparison.Ordinal);
        Assert.True(File.Exists(protection.HookScriptPath));
    }

    [Fact]
    public void User_authored_axiom_file_is_not_overwritten()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".copilot", "hooks"));
        CreateFakePython(temp.Root);
        var hooks = Path.Combine(temp.Root, ".copilot", "hooks", "axiom.json");
        File.WriteAllText(hooks, """{"user":true}""");

        var protection = new CopilotProtection(temp.Root, temp.Root);
        Assert.False(protection.EnsureInstalled());
        Assert.Equal("""{"user":true}""", File.ReadAllText(hooks));
    }

    [Fact]
    public void Remove_deletes_only_the_managed_hook_file()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".copilot"));
        CreateFakePython(temp.Root);

        var protection = new CopilotProtection(temp.Root, temp.Root);
        Assert.True(protection.EnsureInstalled());
        protection.Remove();

        Assert.False(File.Exists(protection.HooksPath));
        Assert.False(File.Exists(protection.HookScriptPath));
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
            Root = Path.Combine(Path.GetTempPath(), $"axiom-copilot-{Guid.NewGuid():N}");
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
