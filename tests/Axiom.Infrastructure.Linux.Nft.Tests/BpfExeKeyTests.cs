// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Axiom.Infrastructure.Linux.Bpf;
using Axiom.Infrastructure.Linux.Diagnostics;
using Axiom.Infrastructure.Unix.Diagnostics;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

/// <summary>
/// The BPF exe key must equal what axiom_connect.bpf.c reads: MAJOR/MINOR of
/// <c>exe_file->f_inode->i_sb->s_dev</c> and <c>i_ino</c>. On btrfs <c>stat</c>'s st_dev is a
/// per-subvolume anonymous device (0:35 on Fedora 45) while the superblock is 0:33, which only
/// /proc/self/mountinfo field 3 reports (docs/LINUX_EBPF.md §3.1).
/// </summary>
public sealed class BpfExeKeyTests
{
    private static readonly Guid RuleA = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");

    /// <summary>Fedora 45 default layout (trimmed from the VM): btrfs subvolumes root and home on one superblock 0:33.</summary>
    internal const string FedoraBtrfs =
        "65 1 0:33 /root / rw,relatime shared:1 - btrfs /dev/vda3 rw,seclabel,compress=zstd:1,discard=async,space_cache=v2,subvolid=257,subvol=/root\n" +
        "24 65 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw\n" +
        "93 65 252:2 / /boot rw,relatime shared:60 - ext4 /dev/vda2 rw,seclabel\n" +
        "97 65 0:33 /home /home rw,relatime shared:62 - btrfs /dev/vda3 rw,seclabel,compress=zstd:1,discard=async,space_cache=v2,subvolid=256,subvol=/home\n";

    private const string Mixed =
        "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw,errors=remount-ro\n" +
        "30 22 253:1 / /usr rw,relatime shared:5 - xfs /dev/mapper/vg-usr rw,attr2,inode64\n" +
        "31 30 253:4 / /usr/local rw,relatime shared:6 master:2 - xfs /dev/mapper/vg-local rw\n" +
        "40 22 8:5 /data/apps /opt/apps rw,relatime shared:9 - ext4 /dev/sda5 rw\n" +
        "41 22 8:6 / /mnt/my\\040disk rw,relatime - ext4 /dev/sda6 rw\n" +
        "50 22 0:60 / /var/lib/containers/merged rw,relatime - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w\n" +
        "not a mountinfo line\n" +
        "51 22 8:7 / /srv rw - ext4 /dev/sda7 rw\n" +
        "52 22 8:8 / /srv rw - ext4 /dev/sda8 rw\n";

    [Fact]
    public void Planner_keys_a_btrfs_exe_by_the_superblock_dev_from_mountinfo_not_the_subvolume_st_dev()
    {
        var inodes = new FakeInodes { MountInfo = FedoraBtrfs };
        inodes.Files["/usr/bin/curl"] = new BpfInode(0, 35, 3056); // stat -L -c '%Hd %Ld %i' on Fedora 45
        var plan = BpfVerdictPlanner.Plan([Specs.Block("/usr/bin/curl", RuleA)], 3, new AppCgroupManager(new FakeCgroupFs()), inodes);

        var exe = Assert.Single(plan.Entries, entry => entry.Map == BpfLayout.ExeMap);
        Assert.Equal(BpfLayout.HexString(BpfLayout.ExeKey(0, 33, 3056)), exe.KeyHex);
        Assert.Contains("dev 0:33", exe.Describe, StringComparison.Ordinal);
        Assert.Contains("btrfs", exe.Describe, StringComparison.Ordinal);
        Assert.Contains("stat 0:35", exe.Describe, StringComparison.Ordinal);
        Assert.Empty(plan.Uncovered);
    }

    [Fact]
    public void Planner_resolves_symlinks_before_choosing_the_mount()
    {
        var inodes = new FakeInodes { MountInfo = Mixed };
        inodes.Files["/bin/curl"] = new BpfInode(253, 1, 42);
        inodes.RealPaths["/bin/curl"] = "/usr/bin/curl";
        var plan = BpfVerdictPlanner.Plan([Specs.Block("/bin/curl", RuleA)], 1, new AppCgroupManager(new FakeCgroupFs()), inodes);

        var exe = Assert.Single(plan.Entries, entry => entry.Map == BpfLayout.ExeMap);
        Assert.Equal(BpfLayout.HexString(BpfLayout.ExeKey(253, 1, 42)), exe.KeyHex);
    }

    [Fact]
    public void Planner_leaves_the_rule_to_nftables_when_the_superblock_dev_cannot_be_proven()
    {
        var unreadable = new FakeInodes { MountInfo = null };
        unreadable.Files["/usr/bin/curl"] = new BpfInode(8, 2, 7);
        var plan = BpfVerdictPlanner.Plan([Specs.Block("/usr/bin/curl", RuleA)], 1, new AppCgroupManager(new FakeCgroupFs()), unreadable);
        Assert.Equal(0, plan.ExeEntries);
        Assert.Contains("mountinfo", Assert.Single(plan.Uncovered).Reason, StringComparison.Ordinal);

        var mismatch = new FakeInodes { MountInfo = Mixed };
        mismatch.Files["/usr/bin/curl"] = new BpfInode(0, 99, 7); // xfs never reports a foreign st_dev
        plan = BpfVerdictPlanner.Plan([Specs.Block("/usr/bin/curl", RuleA)], 1, new AppCgroupManager(new FakeCgroupFs()), mismatch);
        Assert.Equal(0, plan.ExeEntries);
        Assert.Contains("does not match", Assert.Single(plan.Uncovered).Reason, StringComparison.Ordinal);

        var overlay = new FakeInodes { MountInfo = Mixed };
        overlay.Files["/var/lib/containers/merged/usr/bin/curl"] = new BpfInode(0, 60, 7);
        plan = BpfVerdictPlanner.Plan([Specs.Block("/var/lib/containers/merged/usr/bin/curl", RuleA)], 1, new AppCgroupManager(new FakeCgroupFs()), overlay);
        Assert.Equal(0, plan.ExeEntries);
        Assert.Contains("overlay", Assert.Single(plan.Uncovered).Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Sync_does_not_report_a_rule_as_bpf_covered_when_only_its_cgroup_key_could_be_written()
    {
        using var temp = new TempDirectory();
        var bpf = Path.Combine(temp.Path, "image", "bpf");
        Directory.CreateDirectory(bpf);
        File.WriteAllText(Path.Combine(bpf, BpfEnginePaths.ObjectFileName), string.Empty);
        File.WriteAllText(Path.Combine(bpf, BpfEnginePaths.EventsHelperName), string.Empty);
        var btf = Path.Combine(temp.Path, "vmlinux");
        File.WriteAllText(btf, string.Empty);
        var paths = BpfEnginePaths.ForImage(Path.Combine(temp.Path, "image")) with
        {
            PinDirectory = Path.Combine(temp.Path, "pins"),
            CgroupRoot = Path.Combine(temp.Path, "cgroup"),
            BtfFile = btf,
            BpfFs = temp.Path,
        };
        var runner = new FakeBpftool(paths.PinDirectory);
        var fs = new FakeCgroupFs();
        fs.AppPaths["/usr/bin/curl"] = "/usr/bin/curl";
        var cgroups = new AppCgroupManager(fs);
        var inodes = new FakeInodes { MountInfo = null };
        inodes.Files["/usr/bin/curl"] = new BpfInode(0, 35, 3056);
        Assert.True(cgroups.TryResolve("/usr/bin/curl", out var cgroup, out _));
        inodes.CgroupIds[cgroup] = 93;
        using var engine = new BpfEngine(runner, paths, inodes, cgroups, null, _ => null, _ => null, new CollectingSink(), privileged: true, TimeProvider.System);
        await engine.StartAsync(CancellationToken.None);
        Assert.True(engine.Active);

        var spec = Specs.Block("/usr/bin/curl", RuleA);
        var result = await engine.SyncAsync([new ManagedRule { ManagedRuleId = RuleA, OsRuleName = "Axiom-x", OwnershipGroup = OwnedRuleOwnership.GroupName, Spec = spec, State = RuleState.Applied }], 2, CancellationToken.None);

        Assert.DoesNotContain(RuleA, result.CoveredRules);
        Assert.Contains(result.Uncovered, rule => rule.RuleId == RuleA && rule.Reason.Contains("mountinfo", StringComparison.Ordinal));
        await engine.StopAsync();
    }

    [Fact]
    public void Mountinfo_parses_btrfs_subvolumes_ext4_xfs_overlay_and_bind_mounts()
    {
        var fedora = MountInfoTable.Parse(FedoraBtrfs);
        var root = fedora.Entries[0];
        Assert.Equal(new MountInfoEntry(65, 1, 0, 33, "/root", "/", "btrfs", "/dev/vda3"), root);

        var table = MountInfoTable.Parse(Mixed);
        Assert.Equal(8, table.Entries.Count); // the garbage line is skipped
        Assert.Equal("xfs", table.Entries[1].FsType);
        Assert.Equal("overlay", table.Entries.Single(entry => entry.MountPoint == "/var/lib/containers/merged").FsType);
        var bind = table.Find("/opt/apps/tool/bin/tool");
        Assert.NotNull(bind);
        Assert.Equal((8u, 5u, "/data/apps"), (bind.DevMajor, bind.DevMinor, bind.Root));
    }

    [Fact]
    public void Mountinfo_unescapes_octal_sequences_and_matches_paths_with_spaces()
    {
        Assert.Equal("/mnt/my disk", MountInfoTable.Unescape("/mnt/my\\040disk"));
        Assert.Equal("a\tb\nc\\d", MountInfoTable.Unescape("a\\011b\\012c\\134d"));
        Assert.Equal("/plain", MountInfoTable.Unescape("/plain"));
        var hit = MountInfoTable.Parse(Mixed).Find("/mnt/my disk/app");
        Assert.NotNull(hit);
        Assert.Equal(6u, hit.DevMinor);
    }

    [Fact]
    public void Mountinfo_picks_the_longest_component_prefix_and_the_last_overmount()
    {
        var table = MountInfoTable.Parse(Mixed);
        Assert.Equal("/usr/local", table.Find("/usr/local/bin/x")!.MountPoint);
        Assert.Equal("/usr", table.Find("/usr/bin/curl")!.MountPoint);
        Assert.Equal("/usr", table.Find("/usr")!.MountPoint);
        Assert.Equal("/", table.Find("/usrx/bin/curl")!.MountPoint); // component boundary, not string prefix
        Assert.Equal(8u, table.Find("/srv/app")!.DevMinor); // stacked on the same mount point: last wins
        Assert.Null(table.Find("relative/path"));
        Assert.Null(MountInfoTable.Parse(string.Empty).Find("/usr/bin/curl"));
        Assert.Empty(MountInfoTable.Parse(null).Entries);
    }

    [Fact]
    public void Exe_key_resolution_explains_its_source()
    {
        var fedora = MountInfoTable.Parse(FedoraBtrfs);
        var btrfs = BpfExeKey.Resolve("/usr/bin/curl", new BpfInode(0, 35, 3056), fedora);
        Assert.Equal(new BpfInode(0, 33, 3056), btrfs.Key);
        Assert.Contains("btrfs", btrfs.Detail, StringComparison.Ordinal);
        Assert.Contains("subvolume", btrfs.Detail, StringComparison.Ordinal);

        var home = BpfExeKey.Resolve("/home/u/bin/tool", new BpfInode(0, 36, 900), fedora);
        Assert.Equal(new BpfInode(0, 33, 900), home.Key);

        var ext4 = BpfExeKey.Resolve("/usr/bin/curl", new BpfInode(8, 2, 5), MountInfoTable.Parse("22 1 8:2 / / rw - ext4 /dev/sda2 rw\n"));
        Assert.Equal(new BpfInode(8, 2, 5), ext4.Key);
        Assert.Contains("mountinfo", ext4.Detail, StringComparison.Ordinal);

        var none = BpfExeKey.Resolve("/usr/bin/curl", new BpfInode(8, 2, 5), MountInfoTable.Parse(string.Empty));
        Assert.Null(none.Key);
        Assert.Contains("no mountinfo entry", none.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("ID=fedora\nVERSION_ID=45\n", "dnf install bpftool")]
    [InlineData("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n", "dnf install bpftool")]
    [InlineData("ID=ubuntu\nID_LIKE=debian\n", "apt install linux-tools-common linux-tools-$(uname -r)")]
    [InlineData("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n", "apt install linux-tools-common linux-tools-$(uname -r)")]
    [InlineData("ID=debian\n", "apt install bpftool")]
    [InlineData("ID=\"opensuse-tumbleweed\"\nID_LIKE=\"opensuse suse\"\n", "zypper install bpftool")]
    [InlineData("ID=arch\n", "install bpftool with the distribution's package manager")]
    [InlineData(null, "install bpftool with the distribution's package manager")]
    public void Bpftool_hint_follows_os_release(string? osRelease, string expected)
    {
        Assert.Contains(expected, BpftoolHint.For(osRelease), StringComparison.Ordinal);
    }

    [Fact]
    public void Doctor_reports_the_exe_key_source_and_the_btrfs_subvolume_device()
    {
        using var temp = new TempDirectory();
        var mountinfo = Path.Combine(temp.Path, "mountinfo");
        File.WriteAllText(mountinfo, FedoraBtrfs);
        var targets = new LinuxDoctorTargets(
            Path.Combine(temp.Path, "axiomd.service"),
            Path.Combine(temp.Path, "image"),
            Path.Combine(temp.Path, "data"),
            Path.Combine(temp.Path, "axiom.sock"),
            Path.Combine(temp.Path, "backup.json"),
            Path.Combine(temp.Path, "protection.json"),
            Path.Combine(temp.Path, "missing-btf"),
            Path.Combine(temp.Path, "pins"))
        {
            MountInfoPath = mountinfo,
        };
        var runner = new ScriptedRunner(line => line switch
        {
            "stat -L -c %Hd %Ld %i /usr/bin/env" => new ProcessResult(0, "0 35 1777\n", string.Empty),
            "realpath -e -- /usr/bin/env" => new ProcessResult(0, "/usr/bin/env\n", string.Empty),
            _ => new ProcessResult(1, string.Empty, "unexpected"),
        });

        var check = new LinuxDoctor(runner, targets, isRoot: false).Collect().Single(check => check.Name == "bpf exe key");
        Assert.Equal(DoctorCheck.Pass, check.Status);
        Assert.Contains("btrfs", check.Detail, StringComparison.Ordinal);
        Assert.Contains("0:33", check.Detail, StringComparison.Ordinal);
        Assert.Contains("0:35", check.Detail, StringComparison.Ordinal);
        Assert.Contains("mountinfo", check.Detail, StringComparison.Ordinal);

        File.WriteAllText(mountinfo, string.Empty);
        var unknown = new LinuxDoctor(runner, targets, isRoot: false).Collect().Single(check => check.Name == "bpf exe key");
        Assert.Equal(DoctorCheck.Warn, unknown.Status);
        Assert.Contains("nftables", unknown.Detail, StringComparison.Ordinal);
    }

    private sealed class ScriptedRunner(Func<string, ProcessResult> answer) : IProcessRunner
    {
        public ProcessResult Run(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout) =>
            answer(string.Join(' ', new[] { Path.GetFileName(fileName) }.Concat(arguments)));
    }
}
