// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.MacOS.Launchd;

namespace Axiom.Infrastructure.MacOS.Tests;

/// <summary>
/// Log continuity after rotation (macOS security validation, check b): newsyslog renames
/// <c>axiomd.log</c> to <c>axiomd.log.0</c> and creates a new file. A daemon that keeps its
/// handle (launchd's stdout) writes every later line into the renamed, then compressed and
/// unlinked file. The daemon log must follow the path: reopen on SIGHUP (newsyslog signals the
/// pid file) and on a detected rotation, and keep the private 0600 mode.
/// </summary>
public sealed class DaemonLogFileTests
{
    [Fact]
    public void NewLinesLandInTheFreshFileAfterRotationIsDetected()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var log = Path.Combine(temp.Path, "axiomd.log");
        var rotated = log + ".0";

        using (var writer = new DaemonLogFile(log, TimeSpan.Zero))
        {
            writer.WriteLine("before rotation");
            File.Move(log, rotated); // what newsyslog does before it creates the new file

            writer.WriteLine("after rotation");
        }

        Assert.Equal("before rotation", File.ReadAllText(rotated).Trim());
        Assert.Equal("after rotation", File.ReadAllText(log).Trim());
        Assert.Equal(MacLogPermissions.FileMode, File.GetUnixFileMode(log));
    }

    [Fact]
    public void NewsyslogCreatedFileIsFollowedAndKeptPrivate()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var log = Path.Combine(temp.Path, "axiomd.log");
        var rotated = log + ".0";

        using (var writer = new DaemonLogFile(log, TimeSpan.Zero))
        {
            writer.WriteLine("first line of a longer log before the size based rotation");
            File.Move(log, rotated);
            // newsyslog creates the replacement itself (mode from the conf); here deliberately 0644.
            File.WriteAllText(log, "logfile turned over\n");
            File.SetUnixFileMode(log, MacDataDirectoryPermissions.SharedFileMode);

            writer.WriteLine("second");
        }

        Assert.DoesNotContain("second", File.ReadAllText(rotated), StringComparison.Ordinal);
        Assert.Equal(["logfile turned over", "second"], File.ReadAllLines(log));
        Assert.Equal(MacLogPermissions.FileMode, File.GetUnixFileMode(log));
    }

    [Fact]
    public void ReopenOnSignalFollowsTheRenamedPathWithoutWaitingForTheCheck()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var log = Path.Combine(temp.Path, "axiomd.log");
        var rotated = log + ".0";

        // The periodic check is effectively off: only the SIGHUP path can move the writer.
        using (var writer = new DaemonLogFile(log, TimeSpan.FromDays(1)))
        {
            writer.WriteLine("one");
            File.Move(log, rotated);
            writer.Reopen();
            writer.WriteLine("two");
            Assert.Equal(1, writer.ReopenCount);
        }

        Assert.Equal("one", File.ReadAllText(rotated).Trim());
        Assert.Equal("two", File.ReadAllText(log).Trim());
        Assert.Equal(MacLogPermissions.FileMode, File.GetUnixFileMode(log));
    }

    [Fact]
    public void WithoutRotationTheSameFileIsAppended()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var log = Path.Combine(temp.Path, "axiomd.log");
        File.WriteAllText(log, "launchd stdout line\n");

        using (var writer = new DaemonLogFile(log, TimeSpan.Zero))
        {
            writer.WriteLine("a");
            writer.Write("b");
            writer.WriteLine();
            Assert.Equal(0, writer.ReopenCount);
        }

        Assert.Equal(["launchd stdout line", "a", "b"], File.ReadAllLines(log));
    }

    [Fact]
    public void DaemonModeAnnouncesEachReopenAtTheTopOfTheNewFile()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var log = Path.Combine(temp.Path, "axiomd.log");

        using (var writer = new DaemonLogFile(log, TimeSpan.FromDays(1), announceReopen: true))
        {
            writer.WriteLine("one");
            File.Move(log, log + ".0");
            writer.Reopen();
            writer.WriteLine("two");
        }

        var lines = File.ReadAllLines(log);
        Assert.Equal(2, lines.Length);
        Assert.Contains($"axiomd[{Environment.ProcessId}]: log reopened (signal), reopen #1", lines[0], StringComparison.Ordinal);
        Assert.Equal("two", lines[1]);
        Assert.Equal("one", File.ReadAllText(log + ".0").Trim());
    }

    [Fact]
    public void PidFileNamesThisProcessForNewsyslog()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var pidFile = Path.Combine(temp.Path, "axiomd.pid");

        DaemonLogFile.WritePidFile(pidFile);

        Assert.Equal(Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture), File.ReadAllText(pidFile).Trim());
        Assert.Equal(MacDataDirectoryPermissions.SharedFileMode, File.GetUnixFileMode(pidFile));
    }
}
