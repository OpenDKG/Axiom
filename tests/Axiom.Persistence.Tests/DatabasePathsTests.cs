// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Persistence;
using Xunit;

namespace Axiom.Persistence.Tests;

public sealed class DatabasePathsTests
{
    [Fact]
    public void Explicit_data_directory_wins_on_every_platform()
    {
        var previous = Environment.GetEnvironmentVariable("AXIOM_DATA_DIR");
        var directory = Path.Combine(Path.GetTempPath(), "axiom-paths-" + Guid.NewGuid().ToString("N"));
        try
        {
            Environment.SetEnvironmentVariable("AXIOM_DATA_DIR", directory);

            Assert.Equal(directory, DatabasePaths.ResolveDataDirectory());
            Assert.Equal(Path.Combine(directory, "axiom.db"), DatabasePaths.ResolveForCurrentProcess());
        }
        finally
        {
            Environment.SetEnvironmentVariable("AXIOM_DATA_DIR", previous);
        }
    }

    [Fact]
    public void Privacy_shield_directory_keeps_the_windows_legacy_location()
    {
        var directory = DatabasePaths.ResolvePrivacyShieldDirectory();

        Assert.True(Path.IsPathFullyQualified(directory));
        if (OperatingSystem.IsWindows())
        {
            Assert.Equal(
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    DatabasePaths.DataDirectoryName),
                directory);
            return;
        }

        Assert.Equal(DatabasePaths.ResolveDataDirectory(), directory);
    }

    [Fact]
    public void Directory_owner_is_read_from_stat()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var directory = Path.Combine(Path.GetTempPath(), "axiom-owner-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            Assert.True(PosixIdentity.TryGetOwnerUserId(directory, out var owner));
            Assert.Equal(PosixIdentity.EffectiveUserId, owner);
        }
        finally
        {
            Directory.Delete(directory);
        }
    }

    [Fact]
    public void Existing_non_private_populated_directory_is_refused_on_unix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var directory = Path.Combine(Path.GetTempPath(), "axiom-shared-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "existing"), "data");
        File.SetUnixFileMode(
            directory,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute);

        try
        {
            Assert.Throws<UnauthorizedAccessException>(() => DatabasePaths.EnsurePrivateDirectory(directory));
            Assert.Equal("data", File.ReadAllText(Path.Combine(directory, "existing")));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Default_directory_is_absolute_and_platform_appropriate()
    {
        var directory = DatabasePaths.ResolveDataDirectory();

        Assert.True(Path.IsPathFullyQualified(directory));
        Assert.NotEmpty(directory);

        if (OperatingSystem.IsWindows())
        {
            Assert.EndsWith("Axiom", directory, StringComparison.Ordinal);
            return;
        }

        Assert.True(
            directory == "/var/lib/axiom" || directory.EndsWith("Axiom", StringComparison.Ordinal),
            $"Unexpected Linux data directory: {directory}");
    }
}
