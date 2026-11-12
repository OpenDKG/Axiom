// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.MacOS;

namespace Axiom.Infrastructure.MacOS.Tests;

/// <summary>Review 2026-11-12 Medium #5: the daemon log directory, log and rotated archives are root-only.</summary>
public sealed class MacLogPermissionsTests
{
    [Fact]
    public void CreatesDirectoryAndLogRootOnlyAndFixesWorldReadableArchives()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var directory = Path.Combine(temp.Path, "Logs", "Axiom");
        var log = Path.Combine(directory, "axiomd.log");

        var created = MacLogPermissions.Enforce(directory, log);

        Assert.Equal(MacLogPermissions.DirectoryMode, File.GetUnixFileMode(directory));
        Assert.Equal(MacLogPermissions.FileMode, File.GetUnixFileMode(log));
        Assert.Equal(0, new FileInfo(log).Length);
        Assert.Contains(log, created);

        // Rotation by newsyslog (or an older install) left archives 0644 and the directory 0755.
        var rotated = Path.Combine(directory, "axiomd.log.0.bz2");
        var older = Path.Combine(directory, "axiomd.log.1.bz2");
        var unrelated = Path.Combine(directory, "other.log");
        foreach (var file in new[] { rotated, older, unrelated })
        {
            File.WriteAllText(file, "x");
            File.SetUnixFileMode(file, MacDataDirectoryPermissions.SharedFileMode);
        }

        File.SetUnixFileMode(directory, MacDataDirectoryPermissions.SharedDirectoryMode);
        File.AppendAllText(log, "line\n");

        var changed = MacLogPermissions.Enforce(directory, log);

        Assert.Equal([directory, rotated, older], changed);
        Assert.Equal(MacLogPermissions.FileMode, File.GetUnixFileMode(rotated));
        Assert.Equal(MacLogPermissions.FileMode, File.GetUnixFileMode(older));
        Assert.Equal(MacDataDirectoryPermissions.SharedFileMode, File.GetUnixFileMode(unrelated)); // not ours
        Assert.Equal("line\n", File.ReadAllText(log)); // never truncated
        Assert.Empty(MacLogPermissions.Enforce(directory, log)); // idempotent
    }

    [Fact]
    public void NewsyslogModeIsSixHundred() => Assert.Equal("600", MacLogPermissions.NewsyslogMode);
}
