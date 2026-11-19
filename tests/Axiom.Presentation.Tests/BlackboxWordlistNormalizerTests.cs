// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class BlackboxWordlistNormalizerTests
{
    [Fact]
    public void Candidate_paths_cover_agent_and_both_hermes_roots()
    {
        var paths = BlackboxWordlistNormalizer.CandidatePaths(@"C:\Users\lab\AppData\Local", @"C:\Users\lab");

        Assert.Equal(3, paths.Count);
        Assert.Contains(paths, p => p.Contains("agent-blackbox", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(paths, p => p.Replace('\\', '/').Contains("AppData/Local/hermes", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(paths, p => p.EndsWith(
            Path.Combine(".hermes", "plugins", "blackbox", "kernel", "crypto_secrets", "bip39_english.txt"),
            StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Normalize_file_converts_crlf_to_lf_when_digest_matches()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"axiom-bip39-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var file = Path.Combine(tempDir, "bip39_english.txt");
            var lf = Encoding.UTF8.GetBytes("abandon\nability\nable\n");
            var expected = Convert.ToHexStringLower(SHA256.HashData(lf));
            var crlf = Encoding.UTF8.GetBytes("abandon\r\nability\r\nable\r\n");
            File.WriteAllBytes(file, crlf);

            Assert.True(BlackboxWordlistNormalizer.NormalizeFile(file, expected));
            Assert.Equal(lf, File.ReadAllBytes(file));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void Normalize_file_leaves_non_matching_file_untouched()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"axiom-bip39-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var file = Path.Combine(tempDir, "bip39_english.txt");
            var original = Encoding.UTF8.GetBytes("not\r\nthe\r\nwordlist\r\n");
            File.WriteAllBytes(file, original);

            Assert.False(BlackboxWordlistNormalizer.NormalizeFile(file));
            Assert.Equal(original, File.ReadAllBytes(file));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }
}
