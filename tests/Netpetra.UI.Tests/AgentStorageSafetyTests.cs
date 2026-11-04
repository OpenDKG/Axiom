// SPDX-License-Identifier: GPL-3.0-or-later
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
        var pluginDirectory = Path.Combine(temp.Root, ".config", "opencode", "plugins");
        Directory.CreateDirectory(pluginDirectory);
        var plugin = Path.Combine(pluginDirectory, "netpetra-blackbox.ts");
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

        Assert.True(File.ReadAllText(plugin).Contains("Managed by Netpetra", StringComparison.Ordinal));
        Assert.NotEmpty(Directory.GetFiles(pluginDirectory, "netpetra-blackbox.ts.netpetra-backup-*"));
    }

    [Fact]
    public void Reparse_point_helper_returns_false_for_a_normal_file()
    {
        using var temp = new TempTree();
        var file = Path.Combine(temp.Root, "normal.txt");
        File.WriteAllText(file, "test");
        Assert.False(StorageSafety.IsReparsePoint(file));
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
