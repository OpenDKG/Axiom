// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class PrivacyShieldPathsTests
{
    [Fact]
    public void Interactive_run_keeps_per_user_state()
    {
        using var temp = new TempRoot();
        var path = PrivacyShieldPaths.ResolveFor(
            "privacy-shield.json",
            userInteractive: true,
            temp.Local,
            temp.Common);

        Assert.Equal(Path.Combine(temp.Local, PrivacyShieldPaths.DirectoryName, "privacy-shield.json"), path);
        Assert.False(Directory.Exists(Path.Combine(temp.Common, PrivacyShieldPaths.DirectoryName)));
    }

    [Fact]
    public void Installed_service_uses_machine_wide_state()
    {
        using var temp = new TempRoot();
        var path = PrivacyShieldPaths.ResolveFor(
            "privacy-shield.json",
            userInteractive: false,
            temp.Local,
            temp.Common);

        Assert.Equal(Path.Combine(temp.Common, PrivacyShieldPaths.DirectoryName, "privacy-shield.json"), path);
    }

    [Fact]
    public void Existing_service_state_is_migrated_from_local_app_data()
    {
        using var temp = new TempRoot();
        var local = Path.Combine(temp.Local, PrivacyShieldPaths.DirectoryName, "privacy-shield.json");
        Directory.CreateDirectory(Path.GetDirectoryName(local)!);
        File.WriteAllText(local, """{"enabled":true}""");

        var path = PrivacyShieldPaths.ResolveFor(
            "privacy-shield.json",
            userInteractive: false,
            temp.Local,
            temp.Common);

        Assert.Equal(Path.Combine(temp.Common, PrivacyShieldPaths.DirectoryName, "privacy-shield.json"), path);
        Assert.Equal("""{"enabled":true}""", File.ReadAllText(path));
        Assert.True(File.Exists(local));
    }

    [Fact]
    public void Existing_machine_state_is_not_overwritten_by_the_legacy_file()
    {
        using var temp = new TempRoot();
        var local = Path.Combine(temp.Local, PrivacyShieldPaths.DirectoryName, "privacy-shield.json");
        var machine = Path.Combine(temp.Common, PrivacyShieldPaths.DirectoryName, "privacy-shield.json");
        Directory.CreateDirectory(Path.GetDirectoryName(local)!);
        Directory.CreateDirectory(Path.GetDirectoryName(machine)!);
        File.WriteAllText(local, """{"enabled":true}""");
        File.WriteAllText(machine, """{"enabled":false}""");

        var path = PrivacyShieldPaths.ResolveFor(
            "privacy-shield.json",
            userInteractive: false,
            temp.Local,
            temp.Common);

        Assert.Equal(machine, path);
        Assert.Equal("""{"enabled":false}""", File.ReadAllText(path));
    }

    private sealed class TempRoot : IDisposable
    {
        private readonly string _root = Path.Combine(
            Path.GetTempPath(),
            $"axiom-paths-{Guid.NewGuid():N}");

        public TempRoot()
        {
            Local = Path.Combine(_root, "local");
            Common = Path.Combine(_root, "common");
            Directory.CreateDirectory(Local);
            Directory.CreateDirectory(Common);
        }

        public string Local { get; }

        public string Common { get; }

        public void Dispose()
        {
            try
            {
                Directory.Delete(_root, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }
}
