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
        Assert.Equal("@origintrail-official/dkg@10.1.0", DkgRelease.PackageSpec);
    }

    private static string Read(string name)
    {
        using var stream = typeof(DkgRelease).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Embedded resource {name} is missing.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
