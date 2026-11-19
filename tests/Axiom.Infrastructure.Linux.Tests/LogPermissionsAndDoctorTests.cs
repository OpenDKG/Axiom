// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Linux.Diagnostics;
using Axiom.Infrastructure.Linux.Systemd;
using Axiom.Infrastructure.Unix;
using Axiom.Infrastructure.Unix.Diagnostics;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Tests;

/// <summary>
/// Review 2026-11-12 Medium #5 on Linux: the journal is the daemon log (root and the adm /
/// systemd-journal groups per systemd policy); anything under <c>/var/log/axiom</c> is root 0700
/// with 0600 files, enforced by the unit, the installer, the daemon start and checked by the doctor.
/// </summary>
public sealed class LogPermissionsAndDoctorTests
{
    [Fact]
    public void EnforceDirectoryTightensAnExistingDirectoryAndItsFilesWithoutCreatingAnything()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var missing = Path.Combine(temp.Path, "var", "log", "axiom");
        Assert.Empty(UnixLogPermissions.EnforceDirectory(missing));
        Assert.False(Directory.Exists(missing)); // journal-only installs get no directory

        Directory.CreateDirectory(missing);
        File.SetUnixFileMode(missing, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute); // the old 0750 unit
        var log = Path.Combine(missing, "axiomd.log");
        var archive = Path.Combine(missing, "axiomd.log.1.gz");
        File.WriteAllText(log, "line\n");
        File.WriteAllText(archive, "x");
        File.SetUnixFileMode(log, UnixDataDirectoryPermissions.SharedFileMode);
        File.SetUnixFileMode(archive, UnixDataDirectoryPermissions.SharedFileMode);

        var changed = UnixLogPermissions.EnforceDirectory(missing);

        Assert.Equal([missing, log, archive], changed);
        Assert.Equal(UnixLogPermissions.DirectoryMode, File.GetUnixFileMode(missing));
        Assert.Equal(UnixLogPermissions.FileMode, File.GetUnixFileMode(log));
        Assert.Equal(UnixLogPermissions.FileMode, File.GetUnixFileMode(archive));
        Assert.Equal("line\n", File.ReadAllText(log));
        Assert.Empty(UnixLogPermissions.EnforceDirectory(missing)); // idempotent
    }

    [Fact]
    public void UnitDeclaresLogsDirectoryModeSevenHundred()
    {
        var unit = SystemdUnit.Build("/usr/libexec/axiom/axiomd", "/var/lib/axiom", "/run/axiom");

        Assert.Contains("LogsDirectory=axiom", unit, StringComparison.Ordinal);
        Assert.Contains("LogsDirectoryMode=0700", unit, StringComparison.Ordinal);
        Assert.DoesNotContain("LogsDirectoryMode=0750", unit, StringComparison.Ordinal);
        Assert.Contains("StateDirectoryMode=0700", unit, StringComparison.Ordinal);
    }

    [Fact]
    public void DoctorChecksTheLogDirectoryAsRootAndSkipsOtherwise()
    {
        using var temp = new TempDirectory();
        var logDirectory = Path.Combine(temp.Path, "var", "log", "axiom");
        var targets = new LinuxDoctorTargets(
            Path.Combine(temp.Path, "axiomd.service"),
            Path.Combine(temp.Path, "image"),
            Path.Combine(temp.Path, "data"),
            Path.Combine(temp.Path, "run", "axiom.sock"),
            Path.Combine(temp.Path, "data", "backup.json"),
            Path.Combine(temp.Path, "data", "protection.json"))
        {
            LogDirectory = logDirectory,
        };

        var unprivileged = new LinuxDoctor(new FakeRunner().On("stat -c", string.Empty, exitCode: 1), targets, isRoot: false).Collect();
        Assert.Contains(unprivileged, check => check.Name == "log directory" && check.Status == DoctorCheck.Skip);

        // Absent directory: journal only, fine.
        var absent = new LinuxDoctor(new FakeRunner().On("stat -c", string.Empty, exitCode: 1), targets, isRoot: true).Collect();
        Assert.Contains(absent, check => check.Name == "log directory" && check.Status == DoctorCheck.Pass && check.Detail.Contains("journal only", StringComparison.Ordinal));

        // Present with the old 0750: warn (the daemon tightens it at start).
        Directory.CreateDirectory(logDirectory);
        var loose = new LinuxDoctor(new FakeRunner().On("stat -c", _ => new ProcessResult(0, $"0 0 41e8 {logDirectory}\n", string.Empty)), targets, isRoot: true).Collect();
        Assert.Contains(loose, check => check.Name == "log directory" && check.Status == DoctorCheck.Warn && check.Detail.Contains("expected root 0700", StringComparison.Ordinal));

        // Present 0700 with a 0644 file: warn naming the file.
        var log = Path.Combine(logDirectory, "axiomd.log");
        File.WriteAllText(log, string.Empty);
        var runner = new FakeRunner().On("stat -c", arguments => new ProcessResult(0, string.Join('\n', arguments.Skip(2).Select(path =>
            path == logDirectory ? $"0 0 41c0 {path}" : $"0 0 81a4 {path}")) + "\n", string.Empty));
        var looseFile = new LinuxDoctor(runner, targets, isRoot: true).Collect();
        Assert.Contains(looseFile, check => check.Name == "log directory" && check.Status == DoctorCheck.Warn && check.Detail.Contains("axiomd.log", StringComparison.Ordinal));

        // Everything private: pass.
        var tight = new FakeRunner().On("stat -c", arguments => new ProcessResult(0, string.Join('\n', arguments.Skip(2).Select(path =>
            path == logDirectory ? $"0 0 41c0 {path}" : $"0 0 8180 {path}")) + "\n", string.Empty));
        var ok = new LinuxDoctor(tight, targets, isRoot: true).Collect();
        Assert.Contains(ok, check => check.Name == "log directory" && check.Status == DoctorCheck.Pass && check.Detail.Contains("1 file(s) 0600", StringComparison.Ordinal));
    }
}
