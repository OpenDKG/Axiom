// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers.Binary;
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Axiom.Infrastructure.Linux.Bpf;
using Axiom.Infrastructure.Linux.Diagnostics;
using Axiom.Infrastructure.Unix.Diagnostics;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

/// <summary>
/// ABI 2 exe key {s_dev, i_ino, btrfs subvolume id} (docs/LINUX_EBPF.md §2.1): btrfs inode numbers are
/// unique per subvolume only, so the kernel side adds <c>BTRFS_I(inode)->root->root_key.objectid</c>
/// (CO-RE) and user space the same id from statx STATX_SUBVOL / BTRFS_IOC_INO_LOOKUP. The loaded
/// program's own key for the daemon's exe is compared with the user-space key (self-check) before any
/// btrfs exe key is trusted; a mismatch drops every exe key.
/// </summary>
public sealed class BtrfsSubvolumeKeyTests
{
    private static readonly Guid RuleA = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");
    private static readonly Guid RuleB = Guid.Parse("7c9e6679-7425-40de-944b-e07fc1f90ae7");

    private static readonly BpfKernelKeyCheck KernelWithBtrfs = new(BpfKernelKeyState.Verified, BtrfsSubvolume: true, "self-check passed");

    /// <summary>Fedora 45 root subvolume (id 256) plus a second subvolume /srv/subB (id 258) on the same superblock 0:33.</summary>
    private const string FedoraTwoSubvolumes =
        BpfExeKeyTests.FedoraBtrfs +
        "120 65 0:33 /subB /srv/subB rw,relatime shared:70 - btrfs /dev/vda3 rw,seclabel,subvolid=258,subvol=/subB\n";

    private static FakeInodes Fedora()
    {
        var inodes = new FakeInodes { MountInfo = FedoraTwoSubvolumes };
        inodes.Files["/usr/bin/curl"] = new BpfInode(0, 35, 3056);
        inodes.Subvolumes["/usr/bin/curl"] = new BpfSubvolumeId(256, "statx");
        return inodes;
    }

    [Fact]
    public void Layout_is_abi_2_with_a_24_byte_key_and_the_subvolume_at_offset_16()
    {
        Assert.Equal(2, BpfLayout.Abi);
        Assert.Equal(24, BpfLayout.ExeKeySize);
        var key = BpfLayout.ExeKey(0, 33, 257, 258);
        Assert.Equal(24, key.Length);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(0, 4)));
        Assert.Equal(33u, BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(4, 4)));
        Assert.Equal(257ul, BinaryPrimitives.ReadUInt64LittleEndian(key.AsSpan(8, 8)));
        Assert.Equal(258ul, BinaryPrimitives.ReadUInt64LittleEndian(key.AsSpan(16, 8)));
        Assert.Equal(new byte[8], BpfLayout.ExeKey(8, 2, 5).AsSpan(16, 8).ToArray());
    }

    [Fact]
    public void Planner_keys_a_btrfs_exe_with_its_subvolume_id_once_the_kernel_reads_it()
    {
        var plan = BpfVerdictPlanner.Plan([Specs.Block("/usr/bin/curl", RuleA)], 3, new AppCgroupManager(new FakeCgroupFs()), Fedora(), KernelWithBtrfs);

        var exe = Assert.Single(plan.Entries, entry => entry.Map == BpfLayout.ExeMap);
        Assert.Equal(BpfLayout.HexString(BpfLayout.ExeKey(0, 33, 3056, 256)), exe.KeyHex);
        Assert.Contains("subvol 256", exe.Describe, StringComparison.Ordinal);
        Assert.Contains("statx", exe.Describe, StringComparison.Ordinal);
        Assert.Empty(plan.Uncovered);
    }

    [Fact]
    public void Same_inode_in_two_subvolumes_gives_two_different_keys()
    {
        // The collision proven on Fedora 45: fresh subvolumes both start at ino 257.
        var inodes = Fedora();
        inodes.Files["/usr/local/bin/toolA"] = new BpfInode(0, 35, 257);
        inodes.Subvolumes["/usr/local/bin/toolA"] = new BpfSubvolumeId(256, "statx");
        inodes.Files["/srv/subB/toolB"] = new BpfInode(0, 37, 257);
        inodes.Subvolumes["/srv/subB/toolB"] = new BpfSubvolumeId(258, "statx");

        var plan = BpfVerdictPlanner.Plan([Specs.Block("/usr/local/bin/toolA", RuleA), Specs.Block("/srv/subB/toolB", RuleB)], 1, new AppCgroupManager(new FakeCgroupFs()), inodes, KernelWithBtrfs);

        var keys = plan.Entries.Where(entry => entry.Map == BpfLayout.ExeMap).Select(entry => entry.KeyHex).ToList();
        Assert.Equal(2, keys.Count);
        Assert.Contains(BpfLayout.HexString(BpfLayout.ExeKey(0, 33, 257, 256)), keys);
        Assert.Contains(BpfLayout.HexString(BpfLayout.ExeKey(0, 33, 257, 258)), keys);
    }

    [Fact]
    public void Non_btrfs_keys_carry_subvolume_0_and_never_ask_for_one()
    {
        var inodes = new FakeInodes();
        inodes.Files["/usr/bin/curl"] = new BpfInode(8, 2, 5);
        var plan = BpfVerdictPlanner.Plan([Specs.Block("/usr/bin/curl", RuleA)], 1, new AppCgroupManager(new FakeCgroupFs()), inodes, KernelWithBtrfs);

        var exe = Assert.Single(plan.Entries, entry => entry.Map == BpfLayout.ExeMap);
        Assert.Equal(BpfLayout.HexString(BpfLayout.ExeKey(8, 2, 5, 0)), exe.KeyHex);
        Assert.Equal(48, exe.KeyHex.Length);
        Assert.Empty(inodes.SubvolumeCalls);
    }

    [Fact]
    public void Btrfs_exe_stays_nft_only_when_the_subvolume_id_cannot_be_proven()
    {
        var inodes = Fedora();
        inodes.Subvolumes.Clear();
        var plan = BpfVerdictPlanner.Plan([Specs.Block("/usr/bin/curl", RuleA)], 1, new AppCgroupManager(new FakeCgroupFs()), inodes, KernelWithBtrfs);

        Assert.DoesNotContain(plan.Entries, entry => entry.Map == BpfLayout.ExeMap);
        var uncovered = Assert.Single(plan.Uncovered);
        Assert.Contains("btrfs subvolume id of /usr/bin/curl could not be read", uncovered.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Btrfs_exe_stays_nft_only_while_the_kernel_side_is_not_confirmed()
    {
        foreach (var kernel in new BpfKernelKeyCheck?[] { null, BpfKernelKeyCheck.Unverified("no record"), new(BpfKernelKeyState.Verified, BtrfsSubvolume: false, "program loaded without btrfs BTF") })
        {
            var plan = BpfVerdictPlanner.Plan([Specs.Block("/usr/bin/curl", RuleA)], 1, new AppCgroupManager(new FakeCgroupFs()), Fedora(), kernel);

            Assert.DoesNotContain(plan.Entries, entry => entry.Map == BpfLayout.ExeMap);
            var uncovered = Assert.Single(plan.Uncovered);
            Assert.Contains("exe key ambiguous on btrfs subvolumes", uncovered.Reason, StringComparison.Ordinal);
            Assert.Contains("btrfs subvolume id", uncovered.Reason, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Kernel_userspace_mismatch_drops_every_exe_key_but_keeps_cgroup_keys()
    {
        var fs = new FakeCgroupFs();
        fs.AppPaths["/usr/bin/curl"] = "/usr/bin/curl";
        var cgroups = new AppCgroupManager(fs);
        Assert.True(cgroups.TryResolve("/usr/bin/curl", out var cgroup, out _));
        var inodes = new FakeInodes();
        inodes.Files["/usr/bin/curl"] = new BpfInode(8, 2, 5);
        inodes.CgroupIds[cgroup] = 93;
        var mismatch = new BpfKernelKeyCheck(BpfKernelKeyState.Mismatch, false, "kernel/userspace exe key mismatch: kernel dev 8:2 ino 6 subvol 0, userspace dev 8:2 ino 5 subvol 0");

        var plan = BpfVerdictPlanner.Plan([Specs.Block("/usr/bin/curl", RuleA)], 1, cgroups, inodes, mismatch);

        Assert.DoesNotContain(plan.Entries, entry => entry.Map == BpfLayout.ExeMap);
        Assert.Single(plan.Entries, entry => entry.Map == BpfLayout.CgroupMap);
        Assert.Contains("kernel/userspace exe key mismatch", Assert.Single(plan.Uncovered).Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Self_check_record_round_trips_and_compares()
    {
        var hex = SelfCheckHex(4242, 1, 0, 33, 9001, 256, 3);
        var record = BpfLayout.ParseSelfCheck(hex);
        Assert.NotNull(record);
        Assert.Equal(4242u, record.TargetTgid);
        Assert.Equal(new BpfInode(0, 33, 9001, 256), record.Key);
        Assert.True(record.BtrfsCoRe);
        Assert.True(record.ExeOnBtrfs);
        Assert.Equal(BpfLayout.SelfCheckSize * 2, BpfLayout.HexString(BpfLayout.SelfCheckRequest(4242)).Length);
        Assert.Equal(4242u, BinaryPrimitives.ReadUInt32LittleEndian(BpfLayout.SelfCheckRequest(4242)));

        var mounts = MountInfoTable.Parse(BpfExeKeyTests.FedoraBtrfs);
        BpfExeKeyResolution Userspace(bool btrfs) => BpfExeKey.Resolve(
            "/usr/libexec/axiom/axiomd",
            new BpfInode(0, 35, 9001),
            mounts,
            new BpfKernelKeyCheck(BpfKernelKeyState.Verified, btrfs, "probe"),
            _ => new BpfSubvolumeId(256, "statx"));

        var ok = BpfKernelKeyCheck.Compare(record, 4242, "/usr/libexec/axiom/axiomd", Userspace);
        Assert.Equal(BpfKernelKeyState.Verified, ok.State);
        Assert.True(ok.BtrfsSubvolume);

        var wrong = BpfKernelKeyCheck.Compare(BpfLayout.ParseSelfCheck(SelfCheckHex(4242, 1, 0, 33, 9001, 5, 3)), 4242, "/usr/libexec/axiom/axiomd", Userspace);
        Assert.Equal(BpfKernelKeyState.Mismatch, wrong.State);
        Assert.Contains("kernel/userspace exe key mismatch", wrong.Detail, StringComparison.Ordinal);

        var none = BpfKernelKeyCheck.Compare(BpfLayout.ParseSelfCheck(SelfCheckHex(4242, 0, 0, 0, 0, 0, 1)), 4242, "/usr/libexec/axiom/axiomd", Userspace);
        Assert.Equal(BpfKernelKeyState.Unverified, none.State);
    }

    [Fact]
    public async Task Engine_self_check_passes_and_a_btrfs_exe_rule_gets_a_connect_time_key()
    {
        using var temp = new TempDirectory();
        var paths = BpfLayerTests.Paths(temp, createObjects: true);
        var runner = new FakeBpftool(paths.PinDirectory);
        var inodes = SelfOnBtrfs();
        using var engine = Engine(runner, paths, inodes, SelfCheckHex(4242, 1, 0, 33, 9001, 256, 3));

        await engine.StartAsync(CancellationToken.None);

        Assert.True(engine.Active);
        Assert.Equal(BpfKernelKeyState.Verified, engine.KernelKeyCheck.State);
        Assert.True(engine.KernelKeyCheck.BtrfsSubvolume);
        Assert.Contains(runner.Calls, call => call.StartsWith($"bpftool map update pinned {paths.MapPin(BpfLayout.SelfCheckMap)} key hex 00 00 00 00 value hex 92 10 00 00", StringComparison.Ordinal));
        var clear = runner.Calls.Last(call => call.StartsWith($"bpftool map update pinned {paths.MapPin(BpfLayout.SelfCheckMap)}", StringComparison.Ordinal));
        Assert.Contains("value hex 00 00 00 00 ", clear, StringComparison.Ordinal);

        await engine.SyncAsync([BpfLayerTests.Managed(Specs.Block("/usr/bin/curl", RuleA))], 4, CancellationToken.None);
        Assert.Contains(runner.Calls, call => call.StartsWith($"bpftool map update pinned {paths.MapPin(BpfLayout.ExeMap)} key hex {string.Join(' ', BpfLayout.HexTokens(BpfLayout.ExeKey(0, 33, 3056, 256)))} value", StringComparison.Ordinal));
        Assert.Empty(engine.Uncovered);
    }

    [Fact]
    public async Task Engine_self_check_mismatch_downgrades_exe_rules_with_the_reason()
    {
        using var temp = new TempDirectory();
        var paths = BpfLayerTests.Paths(temp, createObjects: true);
        var runner = new FakeBpftool(paths.PinDirectory);
        var inodes = SelfOnBtrfs();
        inodes.Files["/usr/bin/env"] = new BpfInode(0, 33, 77); // same dev as the superblock: ext4-like path
        var log = new List<string>();
        using var engine = Engine(runner, paths, inodes, SelfCheckHex(4242, 1, 0, 33, 9002, 256, 3), log);

        await engine.StartAsync(CancellationToken.None);
        await engine.SyncAsync([BpfLayerTests.Managed(Specs.Block("/usr/bin/curl", RuleA))], 4, CancellationToken.None);

        Assert.Equal(BpfKernelKeyState.Mismatch, engine.KernelKeyCheck.State);
        Assert.DoesNotContain(runner.Calls, call => call.StartsWith($"bpftool map update pinned {paths.MapPin(BpfLayout.ExeMap)}", StringComparison.Ordinal));
        Assert.Contains("kernel/userspace exe key mismatch", Assert.Single(engine.Uncovered).Reason, StringComparison.Ordinal);
        Assert.Contains(log, line => line.Contains("kernel/userspace exe key mismatch", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Engine_refuses_an_object_with_the_abi_1_key_layout_and_unpins_it()
    {
        using var temp = new TempDirectory();
        var paths = BpfLayerTests.Paths(temp, createObjects: true);
        Directory.CreateDirectory(paths.MapDirectory);
        File.WriteAllText(paths.MapPin("axiom_exe_verdicts_abi1_leftover"), string.Empty); // an old pin set
        var runner = new FakeBpftool(paths.PinDirectory) { ExeKeyBytes = 16 };
        using var engine = Engine(runner, paths, SelfOnBtrfs(), null);

        await engine.StartAsync(CancellationToken.None);

        Assert.False(engine.Active);
        Assert.Contains("key layout", engine.Status, StringComparison.Ordinal);
        Assert.Contains("16", engine.Status, StringComparison.Ordinal);
        Assert.False(File.Exists(paths.MapPin("axiom_exe_verdicts_abi1_leftover")));
        Assert.False(Directory.Exists(paths.PinDirectory));
        Assert.DoesNotContain(runner.Calls, call => call.StartsWith("bpftool cgroup attach", StringComparison.Ordinal));
    }

    [Fact]
    public void Doctor_live_enforcement_warns_when_the_bpf_layer_is_neutralised()
    {
        using var temp = new TempDirectory();
        var targets = new LinuxDoctorTargets(
            Path.Combine(temp.Path, "axiomd.service"),
            Path.Combine(temp.Path, "image"),
            Path.Combine(temp.Path, "data"),
            Path.Combine(temp.Path, "axiom.sock"),
            Path.Combine(temp.Path, "backup.json"),
            Path.Combine(temp.Path, "protection.json"),
            Path.Combine(temp.Path, "vmlinux"),
            Path.Combine(temp.Path, "pins"));
        var live = new FirewallCapabilityReport
        {
            Status = FirewallCapabilityStatus.Available,
            Reason = "connect-time layer neutralised; nftables only",
            ConnectTimeLayer = new ConnectTimeLayerReport { State = "neutralised", Healthy = false, Attached = false, Status = "neutralised: stale entries could not be deleted" },
        };
        var doctor = new LinuxDoctor(new LiveStateAndCoverageTests.ActiveUnitRunner(new FakeBpftool(Path.Combine(temp.Path, "pins"))), targets, isRoot: true, () => new DoctorLiveState(live, null));

        var check = doctor.Collect().Single(check => check.Name == "live enforcement");

        Assert.Equal(DoctorCheck.Warn, check.Status);
        Assert.Contains("neutralised", check.Detail, StringComparison.Ordinal);
    }

    internal static string SelfCheckHex(uint tgid, uint hits, uint major, uint minor, ulong ino, ulong subvol, uint flags)
    {
        var bytes = new byte[BpfLayout.SelfCheckSize];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0, 4), tgid);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4, 4), hits);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8, 4), major);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12, 4), minor);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(16, 8), ino);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(24, 8), subvol);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(32, 4), flags);
        return BpfLayout.HexString(bytes);
    }

    /// <summary>The daemon itself on Fedora's btrfs root: /proc/4242/exe → /usr/libexec/axiom/axiomd, ino 9001, subvolume 256.</summary>
    private static FakeInodes SelfOnBtrfs()
    {
        var inodes = Fedora();
        inodes.RealPaths["/proc/4242/exe"] = "/usr/libexec/axiom/axiomd";
        inodes.Files["/proc/4242/exe"] = new BpfInode(0, 35, 9001);
        inodes.Files["/usr/libexec/axiom/axiomd"] = new BpfInode(0, 35, 9001);
        inodes.Subvolumes["/usr/libexec/axiom/axiomd"] = new BpfSubvolumeId(256, "statx");
        return inodes;
    }

    /// <summary>An engine whose self-check connect makes the fake "kernel" record <paramref name="recorded"/>.</summary>
    private static BpfEngine Engine(FakeBpftool runner, BpfEnginePaths paths, FakeInodes inodes, string? recorded, List<string>? log = null) =>
        new(runner, paths, inodes, new AppCgroupManager(new FakeCgroupFs()), null, _ => null, _ => null, new CollectingSink(), privileged: true, TimeProvider.System)
        {
            Log = (log ?? []).Add,
            SelfExePath = "/proc/4242/exe",
            SelfPid = 4242,
            SelfCheckConnect = () =>
            {
                if (recorded is not null)
                {
                    runner.Maps[paths.MapPin(BpfLayout.SelfCheckMap)]["00000000"] = recorded;
                }
            },
        };
}
