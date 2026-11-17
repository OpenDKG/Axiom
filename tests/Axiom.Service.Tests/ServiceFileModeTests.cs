// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Privacy;
using Xunit;

namespace Axiom.Service.Tests;

/// <summary>
/// Gate B (#441): service-private stores are owner-only (0600) on Unix; on Windows
/// <see cref="ServiceFiles.SetOwnerOnly"/> is a no-op and the mode is never touched, so the Unix
/// assertions return early there.
/// </summary>
public sealed class ServiceFileModeTests
{
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    [Fact]
    public void Set_owner_only_tightens_a_world_readable_file_on_unix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var path = Path.Combine(Path.GetTempPath(), $"axiom-svcfile-{Guid.NewGuid():N}");
        try
        {
            File.WriteAllText(path, "x");
            File.SetUnixFileMode(path, OwnerOnly | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

            ServiceFiles.SetOwnerOnly(path);

            Assert.Equal(OwnerOnly, File.GetUnixFileMode(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Set_owner_only_on_a_missing_file_does_not_throw()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-svcfile-missing-{Guid.NewGuid():N}");

        // Windows: no-op. Unix: FileNotFoundException is an IOException and is swallowed like any
        // other best-effort failure (the write itself already succeeded).
        Assert.Null(Record.Exception(() => ServiceFiles.SetOwnerOnly(path)));
    }

    [Fact]
    public void Privacy_shield_settings_are_owner_only_on_unix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var directory = Directory.CreateTempSubdirectory("axiom-shield-mode-");
        try
        {
            var path = Path.Combine(directory.FullName, "privacy-shield.json");
            Assert.True(new PrivacyShieldSettingsStore(path).Save(new PrivacyShieldSettings { Port = 5353 }));
            Assert.Equal(OwnerOnly, File.GetUnixFileMode(path));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }
}
