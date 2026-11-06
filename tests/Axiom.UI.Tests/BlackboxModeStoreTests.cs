// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class BlackboxModeStoreTests
{
    [Fact]
    public void SetMode_preserves_yaml_comments_and_creates_a_backup()
    {
        using var temp = new TempTree();
        var config = Path.Combine(temp.Root, ".hermes", "config.yaml");
        Directory.CreateDirectory(Path.GetDirectoryName(config)!);
        File.WriteAllText(config, """
            # keep this comment
            plugins:
              entries:
                blackbox:
                  mode: audit # mode comment
                  severity: high
            """);

        var store = new BlackboxModeStore(temp.Root, temp.Root);
        Assert.True(store.SetMode("block"));

        var updated = File.ReadAllText(config);
        Assert.Contains("# keep this comment", updated, StringComparison.Ordinal);
        Assert.Contains("mode: block # mode comment", updated, StringComparison.Ordinal);
        Assert.Contains("severity: high", updated, StringComparison.Ordinal);
        Assert.Equal("block", store.GetMode());
        Assert.NotEmpty(Directory.GetFiles(
            Path.GetDirectoryName(config)!,
            "config.yaml.axiom-backup-*"));
    }

    private sealed class TempTree : IDisposable
    {
        public TempTree()
        {
            Root = Path.Combine(Path.GetTempPath(), $"axiom-yaml-{Guid.NewGuid():N}");
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
