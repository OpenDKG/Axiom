// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Netpetra.UI.Services;
using Xunit;

namespace Netpetra.UI.Tests;

public sealed class OptionalModuleUninstallerTests
{
    [Fact]
    public void Unmanaged_opencode_plugin_is_never_deleted()
    {
        using var temp = new TempTree();
        var plugin = Path.Combine(
            temp.Root,
            ".config",
            "opencode",
            "plugins",
            "netpetra-blackbox",
            "index.ts");
        Directory.CreateDirectory(Path.GetDirectoryName(plugin)!);
        File.WriteAllText(plugin, "// user-authored plugin\n");

        var uninstaller = new OptionalModuleUninstaller(temp.Root, temp.Root);

        Assert.False(uninstaller.RemoveManagedOpenCodePlugin());
        Assert.True(File.Exists(plugin));
        Assert.Equal("// user-authored plugin\n", File.ReadAllText(plugin));
    }

    [Fact]
    public void Managed_opencode_v2_plugin_is_removed_and_backed_up()
    {
        using var temp = new TempTree();
        var plugin = Path.Combine(
            temp.Root,
            ".config",
            "opencode",
            "plugins",
            "netpetra-blackbox",
            "index.ts");
        Directory.CreateDirectory(Path.GetDirectoryName(plugin)!);
        File.WriteAllText(plugin, "// Managed by Netpetra. test\n");

        var uninstaller = new OptionalModuleUninstaller(temp.Root, temp.Root);

        Assert.True(uninstaller.RemoveManagedOpenCodePlugin());
        Assert.False(File.Exists(plugin));
        Assert.NotEmpty(Directory.GetFiles(Path.GetDirectoryName(plugin)!, "index.ts.netpetra-backup-*"));
    }

    [Fact]
    public void Managed_opencode_v1_fallback_is_removed()
    {
        using var temp = new TempTree();
        var plugin = Path.Combine(temp.Root, ".config", "opencode", "plugins", "netpetra-blackbox.ts");
        Directory.CreateDirectory(Path.GetDirectoryName(plugin)!);
        File.WriteAllText(plugin, "// Managed by Netpetra. test\n");

        var uninstaller = new OptionalModuleUninstaller(temp.Root, temp.Root);

        Assert.True(uninstaller.RemoveManagedOpenCodePlugin());
        Assert.False(File.Exists(plugin));
    }

    private sealed class TempTree : IDisposable
    {
        public TempTree()
        {
            Root = Path.Combine(Path.GetTempPath(), $"netpetra-uninstaller-{Guid.NewGuid():N}");
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
