// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Linux.Firewall;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

public sealed class FirewallIdentityTests
{
    [Fact]
    public void Hash_matches_the_kernel_reference_vector()
    {
        // Independent FNV/rotate implementation over the filesystem device, leaf-to-root
        // components and the filesystem root dentry. Changing the algorithm silently would stop
        // every existing rule matching.
        var (hi, lo) = ExecutableIdentity.HashComponents(["cli", "shm"], deviceMajor: 8, deviceMinor: 1);

        Assert.Equal(15837780116709255656UL, hi);
        Assert.Equal(6786165082427694941UL, lo);
    }

    [Fact]
    public void Same_internal_path_on_two_filesystems_does_not_share_an_identity()
    {
        var first = ExecutableIdentity.HashComponents(["tool"], deviceMajor: 8, deviceMinor: 1);
        var second = ExecutableIdentity.HashComponents(["tool"], deviceMajor: 8, deviceMinor: 2);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void File_system_path_uses_the_mount_root_for_a_bind_mount()
    {
        var mountInfo = TempMountInfo(
            "36 1 0:32 / / rw - ext4 /dev/root rw",
            "44 36 0:41 /srv/opt /mnt/tools rw - ext4 /dev/other rw");

        var path = ExecutableIdentity.ToFileSystemPath("/mnt/tools/app/bin/tool", mountInfo);

        Assert.Equal("/srv/opt/app/bin/tool", path);
    }

    [Fact]
    public void File_system_path_prefers_the_longest_mount_point()
    {
        var mountInfo = TempMountInfo(
            "36 1 0:32 / / rw - ext4 /dev/root rw",
            "44 36 0:41 /data /srv rw - ext4 /dev/other rw",
            "45 44 0:42 / /srv/app rw - ext4 /dev/third rw");

        var path = ExecutableIdentity.ToFileSystemPath("/srv/app/bin/tool", mountInfo);

        Assert.Equal("/bin/tool", path);
    }

    [Fact]
    public void File_system_path_unescapes_mount_points_with_spaces()
    {
        var mountInfo = TempMountInfo("36 1 0:32 / /tmp/a\\040b rw - tmpfs tmpfs rw");

        var path = ExecutableIdentity.ToFileSystemPath("/tmp/a b/tool", mountInfo);

        Assert.Equal("/tool", path);
    }

    [Fact]
    public void Resolve_rejects_relative_missing_and_shallow_paths()
    {
        Assert.False(ExecutableIdentity.TryResolve("usr/bin/true", out _, out var relative));
        Assert.Contains("absolute", relative, StringComparison.OrdinalIgnoreCase);

        Assert.False(ExecutableIdentity.TryResolve("/definitely/not/here/executable", out _, out var missing));
        Assert.Contains("does not exist", missing, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Resolve_accepts_an_existing_absolute_executable_and_hashes_it()
    {
        var binary = TestBinaries.ExistingExecutable();
        Assert.True(ExecutableIdentity.TryResolve(binary, out var identity, out var error), error);

        Assert.NotNull(identity);
        Assert.StartsWith("/", identity.FileSystemPath, StringComparison.Ordinal);
        Assert.NotEqual(0UL, identity.HashHi | identity.HashLo);
        Assert.Equal(16, identity.KeyBytes().Length);
    }

    private static string TempMountInfo(params string[] lines)
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-mountinfo-{Guid.NewGuid():N}");
        File.WriteAllLines(path, lines);
        return path;
    }
}
