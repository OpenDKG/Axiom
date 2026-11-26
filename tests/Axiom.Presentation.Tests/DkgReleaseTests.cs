// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class DkgReleaseTests
{
    [Fact]
    public void Embedded_npm_manifest_and_lock_pin_the_installer_version()
    {
        var assembly = typeof(DkgRelease).Assembly;

        using var manifest = JsonDocument.Parse(
            Read("Axiom.Presentation.Resources.dkg.package.json"));
        Assert.Equal(
            DkgRelease.PinnedVersion,
            manifest.RootElement
                .GetProperty("dependencies")
                .GetProperty(DkgRelease.PackageName)
                .GetString());

        using var lockFile = JsonDocument.Parse(
            Read("Axiom.Presentation.Resources.dkg.package-lock.json"));
        var packages = lockFile.RootElement.GetProperty("packages");
        Assert.Equal(
            DkgRelease.PinnedVersion,
            packages.GetProperty("node_modules/" + DkgRelease.PackageName).GetProperty("version").GetString());
        Assert.Equal(
            DkgRelease.PinnedVersion,
            packages.GetProperty(string.Empty)
                .GetProperty("dependencies")
                .GetProperty(DkgRelease.PackageName)
                .GetString());
    }

    [Fact]
    public void Pinned_release_targets_the_testnet_the_installer_initialises()
    {
        Assert.Equal("testnet", DkgRelease.Network);
        Assert.Equal("@origintrail-official/dkg@10.1.2", DkgRelease.PackageSpec);
    }

    /// <summary>
    /// The manifest's npm overrides must stay in effect in the lock, so that moving the pinned DKG
    /// release cannot silently bring older copies of these packages back.
    /// </summary>
    [Theory]
    [InlineData("lodash-es", "4.18.1")]
    [InlineData("dompurify", "3.4.17")]
    [InlineData("@fastify/busboy", "3.2.2")]
    [InlineData("undici", "6.29.1")]
    public void Lock_holds_no_copy_older_than_the_patched_version(string package, string minimum)
    {
        using var lockFile = JsonDocument.Parse(
            Read("Axiom.Presentation.Resources.dkg.package-lock.json"));
        var old = lockFile.RootElement.GetProperty("packages").EnumerateObject()
            .Where(entry => entry.Name.EndsWith("node_modules/" + package, StringComparison.Ordinal))
            .Select(entry => (entry.Name, Version: entry.Value.GetProperty("version").GetString()!))
            .Where(copy => Version.Parse(copy.Version) < Version.Parse(minimum))
            .ToList();

        Assert.Empty(old);
    }

    private static string Read(string name)
    {
        using var stream = typeof(DkgRelease).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Embedded resource {name} is missing.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
