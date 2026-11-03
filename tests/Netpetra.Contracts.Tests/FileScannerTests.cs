// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Cryptography;
using System.Text;
using Netpetra.Contracts.Files;
using Xunit;

namespace Netpetra.Contracts.Tests;

public sealed class FileScannerTests
{
    [Fact]
    public async Task Sha256_matches_the_known_value_for_abc()
    {
        var path = Path.Combine(Path.GetTempPath(), $"netpetra-hash-{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(path, "abc");

        try
        {
            var hash = await FileHasher.ComputeSha256Async(path);

            Assert.Equal(
                Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("abc"))),
                hash);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Scanner_hashes_files_and_skips_oversized_ones()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"netpetra-scan-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);

        try
        {
            var small = Path.Combine(directory, "small.txt");
            var large = Path.Combine(directory, "large.txt");
            await File.WriteAllTextAsync(small, "hello");
            await File.WriteAllBytesAsync(large, new byte[32]);

            var results = await FileScanner.ScanAsync(directory, maxFiles: 10, maxFileBytes: 16);

            var smallResult = Assert.Single(results, entry => entry.Path == small);
            Assert.NotNull(smallResult.Sha256);
            Assert.Equal(5, smallResult.SizeBytes);

            var largeResult = Assert.Single(results, entry => entry.Path == large);
            Assert.Null(largeResult.Sha256);
            Assert.Equal("larger than limit", largeResult.SkippedReason);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
