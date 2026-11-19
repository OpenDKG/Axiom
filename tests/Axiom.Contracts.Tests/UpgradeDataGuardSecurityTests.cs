// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Contracts.Blackbox;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class UpgradeDataGuardSecurityTests
{
    [Fact]
    public void VerifyAndRestore_rejects_path_traversal_entries_in_manifest()
    {
        var root = Path.Combine(Path.GetTempPath(), $"axiom-upgradeguard-{Guid.NewGuid():N}");
        var backupDir = Path.Combine(root, "backup");
        var localDir = Path.Combine(root, "local");
        var outsideFile = Path.Combine(root, "outside.txt");
        Directory.CreateDirectory(backupDir);
        Directory.CreateDirectory(localDir);

        try
        {
            File.WriteAllText(outsideFile, "secret");
            var manifest = new
            {
                CreatedUtc = DateTimeOffset.UtcNow,
                Entries = new[]
                {
                    new { RelativePath = "../outside.txt", Length = 6L },
                    new { RelativePath = Path.Combine(root, "outside.txt"), Length = 6L },
                },
            };
            File.WriteAllText(
                Path.Combine(backupDir, "manifest.json"),
                JsonSerializer.Serialize(manifest));

            var result = UpgradeDataGuard.VerifyAndRestore(backupDir, localDir);

            Assert.Empty(result.Restored);
            Assert.Equal(2, result.Failed.Count);
            Assert.False(File.Exists(Path.Combine(localDir, "outside.txt")));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }
}
