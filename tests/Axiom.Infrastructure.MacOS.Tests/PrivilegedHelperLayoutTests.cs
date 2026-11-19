// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Infrastructure.MacOS.Launchd;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class PrivilegedHelperLayoutTests
{
    private const string Helper = "/Library/PrivilegedHelperTools/com.axiom.service";

    [Fact]
    public void StatOutputIsParsed()
    {
        var entries = UnixFileStat.Parse(
            "0 0 40755 /Library/PrivilegedHelperTools/com.axiom.service\n" +
            "0 0 100755 /Library/PrivilegedHelperTools/com.axiom.service/axiomd\n" +
            "501 20 100644 /Library/Application Support/Axiom/with space.json\n" +
            "0 0 140666 /var/run/axiom/axiom.sock\n" +
            "garbage line\n" +
            "x y z w\n");

        Assert.Equal(4, entries.Count);
        Assert.True(entries[0].IsDirectory);
        Assert.Equal(0x1ED, entries[0].Permissions);
        Assert.Equal("755", entries[0].PermissionsOctal);
        Assert.False(entries[1].IsDirectory);
        Assert.True(entries[1].IsRootOwned);
        Assert.Equal("/Library/Application Support/Axiom/with space.json", entries[2].Path);
        Assert.Equal(501u, entries[2].Uid);
        Assert.False(entries[2].IsGroupOrWorldWritable);
        Assert.True(entries[3].IsSocket);
        Assert.True(entries[3].IsGroupOrWorldWritable);
        Assert.Equal("uid=0 gid=0 mode=666", entries[3].Describe());
    }

    [Fact]
    public void AuditPassesForARootOwnedReadOnlyTree()
    {
        var entries = new[]
        {
            new UnixFileEntry(Helper, 0, 0, 0x41ED),
            new UnixFileEntry(Helper + "/axiomd", 0, 0, 0x81ED),
            new UnixFileEntry(Helper + "/Axiom.Core.dll", 0, 0, 0x81A4),
            new UnixFileEntry(Helper + "/sub", 0, 0, 0x41ED),
        };

        Assert.Empty(PrivilegedHelperLayout.Audit(Helper, entries));
    }

    [Fact]
    public void AuditReportsEveryProblem()
    {
        var entries = new[]
        {
            new UnixFileEntry(Helper, 0, 0, 0x41FD),
            new UnixFileEntry(Helper + "/axiomd", 501, 20, 0x81A4),
            new UnixFileEntry(Helper + "/Axiom.Core.dll", 0, 0, 0x81B6),
        };

        var problems = PrivilegedHelperLayout.Audit(Helper, entries);

        Assert.Contains(problems, problem => problem.Contains(Helper + " is group- or world-writable", StringComparison.Ordinal));
        Assert.Contains(problems, problem => problem.Contains("axiomd is owned by uid 501", StringComparison.Ordinal));
        Assert.Contains(problems, problem => problem.Contains("axiomd is not executable", StringComparison.Ordinal));
        Assert.Contains(problems, problem => problem.Contains("Axiom.Core.dll is group- or world-writable", StringComparison.Ordinal));
        Assert.Equal(4, problems.Count);
    }

    [Fact]
    public void AuditFailsClosedWhenDirectoryOrDaemonAreMissing()
    {
        Assert.Equal(2, PrivilegedHelperLayout.Audit(Helper, []).Count);
        Assert.Single(PrivilegedHelperLayout.Audit(Helper, [new UnixFileEntry(Helper, 0, 0, 0x41ED)]));
    }

    [Fact]
    public void CopiedEntriesGetFinalModes()
    {
        Assert.Equal(PrivilegedHelperLayout.DirectoryMode, PrivilegedHelperLayout.ModeFor(true, UnixFileMode.None));
        Assert.Equal(PrivilegedHelperLayout.ExecutableMode, PrivilegedHelperLayout.ModeFor(false, UnixFileMode.UserRead | UnixFileMode.UserExecute));
        Assert.Equal(PrivilegedHelperLayout.FileMode, PrivilegedHelperLayout.ModeFor(false, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherWrite));
        Assert.Equal("/Library/PrivilegedHelperTools/com.axiom.service/axiomd", PrivilegedHelperLayout.DaemonPath);
    }
}
