// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Netpetra.UI.Services;
using Xunit;

namespace Netpetra.UI.Tests;

public sealed class ClineProtectionTests
{
    [Fact]
    public async Task Probe_refuses_a_user_authored_Cline_hook()
    {
        using var temp = new TempTree();
        var hooksDirectory = Path.Combine(temp.Root, "Documents", "Cline", "Hooks");
        Directory.CreateDirectory(hooksDirectory);
        var hook = Path.Combine(hooksDirectory, "PreToolUse.py");
        File.WriteAllText(hook, "# user-authored hook\n");
        CreateFakePython(temp.Root);

        var result = await new AgentHookProbe(temp.Root, temp.Root)
            .TestAsync("cline", CancellationToken.None);

        Assert.Equal("FAIL", result.Status);
        Assert.Contains("not Axiom-managed", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Install_writes_marker_owned_PreToolUse()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, "Documents", "Cline"));
        CreateFakePython(temp.Root);

        var protection = new ClineProtection(temp.Root, temp.Root);
        Assert.True(protection.IsClineDetected);
        Assert.True(protection.EnsureInstalled());
        Assert.True(protection.IsInstalled);
        var script = File.ReadAllText(protection.HookPath);
        Assert.Contains("Managed by Netpetra", script, StringComparison.Ordinal);
        Assert.Contains(
            $"ROOT = Path(r\"{Path.Combine(temp.Root, "Netpetra", "modules", "blackbox", "agent-blackbox")}\")",
            script,
            StringComparison.Ordinal);
    }

    [Fact]
    public void User_authored_PreToolUse_is_not_overwritten()
    {
        using var temp = new TempTree();
        var hooksDirectory = Path.Combine(temp.Root, "Documents", "Cline", "Hooks");
        Directory.CreateDirectory(hooksDirectory);
        CreateFakePython(temp.Root);
        var hook = Path.Combine(hooksDirectory, "PreToolUse.py");
        File.WriteAllText(hook, "# user hook\n");

        var protection = new ClineProtection(temp.Root, temp.Root);
        Assert.False(protection.EnsureInstalled());
        Assert.Equal("# user hook\n", File.ReadAllText(hook));
    }

    [Fact]
    public void Remove_deletes_only_the_marker_owned_hook()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, "Documents", "Cline"));
        CreateFakePython(temp.Root);

        var protection = new ClineProtection(temp.Root, temp.Root);
        Assert.True(protection.EnsureInstalled());
        protection.Remove();
        Assert.False(File.Exists(protection.HookPath));
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
            Root = Path.Combine(Path.GetTempPath(), $"netpetra-cline-{Guid.NewGuid():N}");
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
