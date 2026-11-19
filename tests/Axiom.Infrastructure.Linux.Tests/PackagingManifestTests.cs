// SPDX-License-Identifier: GPL-3.0-or-later
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

/// <summary>
/// Guards the nfpm contents mapping that the .deb and .rpm must agree on. nfpm symlink entries
/// use installed filesystem paths for both <c>src</c> (the link target) and <c>dst</c> (the link),
/// unlike regular file/tree entries whose <c>src</c> is on the build host. Staging the launcher
/// target would ship a link into the build directory, so this pins the exact mapping.
/// </summary>
public sealed class PackagingManifestTests
{
    [Fact]
    public void Rpm_launcher_symlink_targets_the_installed_payload_not_the_staging_tree()
    {
        var lines = File.ReadAllLines(ManifestPath());
        var entry = FindContentsEntry(lines, "dst: /usr/bin/axiom-firewall");

        Assert.Contains(entry, line => Normalize(line) == "src: /usr/lib/axiom-firewall/Axiom");
        Assert.Contains(entry, line => Normalize(line) == "type: symlink");
        Assert.DoesNotContain(entry, line => line.Contains("@STAGE@", StringComparison.Ordinal));
    }

    [Fact]
    public void Rpm_payload_tree_is_staged_from_the_build_host()
    {
        var lines = File.ReadAllLines(ManifestPath());
        var entry = FindContentsEntry(lines, "dst: /usr/lib/axiom-firewall");

        Assert.Contains(entry, line => Normalize(line) == "src: \"@STAGE@/usr/lib/axiom-firewall\"");
        Assert.Contains(entry, line => Normalize(line) == "type: tree");
    }

    private static string Normalize(string line) => line.Trim().TrimStart('-').Trim();

    private static List<string> FindContentsEntry(string[] lines, string dstLine)
    {
        var index = Array.FindIndex(lines, line => line.Trim() == dstLine);
        Assert.True(index > 0, $"no contents entry with '{dstLine}'");

        var start = index;
        while (start > 0 && !lines[start].TrimStart().StartsWith("- src:", StringComparison.Ordinal))
        {
            start--;
        }

        Assert.StartsWith("- src:", lines[start].TrimStart(), StringComparison.Ordinal);
        return lines[start..Math.Min(index + 2, lines.Length - 1)].ToList();
    }

    private static string ManifestPath()
    {
        var directoryInfo = new DirectoryInfo(AppContext.BaseDirectory);
        while (directoryInfo is not null && !File.Exists(Path.Combine(directoryInfo.FullName, "Axiom.sln")))
        {
            directoryInfo = directoryInfo.Parent;
        }

        Assert.NotNull(directoryInfo);
        return Path.Combine(directoryInfo!.FullName, "packaging", "linux", "nfpm.yaml.in");
    }
}
