// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Bpf;
using Axiom.Infrastructure.Linux.Nft;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

/// <summary>
/// PR #276 review, LNX-1: the eBPF verdict maps are an enforcement layer of their own. A rule is
/// only "removed" once every attached layer stopped enforcing it, and a map write that failed must
/// surface in the adapter's result/state, never be swallowed as a log line.
/// </summary>
public sealed class BpfEffectiveStateTests
{
    private static readonly Guid RuleA = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");

    /// <summary>Adapter + real <see cref="BpfEngine"/> over the fake bpftool, attached and synced.</summary>
    internal sealed class Harness : IDisposable
    {
        public TempDirectory Dir { get; } = new();

        public FakeNftRunner Nft { get; } = new();

        public FakeCgroupFs Fs { get; } = new();

        public FakeInodes Inodes { get; } = new();

        public FakeBpftool Bpftool { get; }

        public BpfEnginePaths BpfPaths { get; }

        public List<string> Log { get; } = [];

        public ManualTimeProvider Time { get; } = new(new DateTimeOffset(2026, 11, 12, 12, 0, 0, TimeSpan.Zero));

        public NftFirewallPolicyAdapter Adapter { get; }

        public BpfEngine Engine { get; }

        public string CurlCgroup { get; }

        public Harness()
        {
            Fs.AppPaths["/usr/bin/curl"] = "/usr/bin/curl";
            Fs.AppPaths["/usr/bin/wget"] = "/usr/bin/wget";
            Inodes.Files["/usr/bin/curl"] = new BpfInode(8, 2, 51643045);
            Inodes.Files["/usr/bin/wget"] = new BpfInode(8, 2, 777);
            var cgroups = new AppCgroupManager(Fs);
            Assert.True(cgroups.TryResolve("/usr/bin/curl", out var curlCgroup, out _));
            CurlCgroup = curlCgroup;
            Inodes.CgroupIds[curlCgroup] = 93;
            BpfPaths = BpfTestPaths.Create(Dir);
            Bpftool = new FakeBpftool(BpfPaths.PinDirectory);
            Engine = new BpfEngine(Bpftool, BpfPaths, Inodes, cgroups, null, _ => null, _ => null, new CollectingSink(), privileged: true, Time) { Log = Log.Add, ReconcileBackoff = TimeSpan.FromMilliseconds(1) };
            Adapter = new NftFirewallPolicyAdapter(new NftEnginePaths(Path.Combine(Dir.Path, "filter")), new NftTable(Nft), cgroups, new CollectingSink(), () => true, Time)
            {
                VerdictLayer = Engine,
            };
        }

        public async Task AttachAsync()
        {
            await Engine.StartAsync(CancellationToken.None);
            Assert.True(Engine.Active);
        }

        public void Dispose()
        {
            Engine.Dispose();
            Adapter.Dispose();
            Dir.Dispose();
        }
    }

    [Fact]
    public async Task Unscoped_outbound_block_is_reflected_in_nft_and_in_the_bpf_maps()
    {
        using var h = new Harness();
        await h.AttachAsync();

        var result = await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(RuleState.Applied, result.State);
        Assert.Contains("socket cgroupv2 level 2 \"axiom.slice/a-", h.Nft.AppliedScript, StringComparison.Ordinal);
        Assert.Equal(2, h.Engine.AppliedEntries.Count);
        Assert.Equal(1, h.Engine.Generation);
        Assert.Contains(h.Bpftool.Calls, call => call.StartsWith($"bpftool map update pinned {h.BpfPaths.MapPin(BpfLayout.ExeMap)} key hex 08 00 00 00 02 00 00 00 a5 02 14 03 00 00 00 00", StringComparison.Ordinal));
        Assert.Contains(h.Bpftool.Calls, call => call.StartsWith($"bpftool map update pinned {h.BpfPaths.MapPin(BpfLayout.CgroupMap)} key hex 5d 00 00 00 00 00 00 00", StringComparison.Ordinal));
        Assert.Equal(FilterEnforcementState.Verified, h.Adapter.Enforcement!.State);
    }

    [Fact]
    public async Task Remove_whose_bpf_map_delete_failed_must_not_report_a_verified_removal()
    {
        using var h = new Harness();
        await h.AttachAsync();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        Assert.Equal(2, h.Engine.AppliedEntries.Count);

        // bpftool map delete fails for every key: the stale exe + cgroup verdicts keep blocking curl.
        h.Bpftool.FailPrefixes.Add("bpftool map delete");
        var removal = await h.Adapter.RemoveOwnedRuleAsync(RuleA, CancellationToken.None);

        Assert.NotNull(h.Nft.TableGeneration); // nft side republished without the rule; BPF side still holds it
        Assert.False(removal.Success && removal.VerifiedUtc is not null, "a removal with a stale BPF entry must not be reported as verified");
        Assert.NotEqual(RuleState.Desired, removal.State);
        Assert.NotNull(removal.ErrorCode);
        Assert.Contains("BPF", removal.ErrorMessage ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(FilterEnforcementState.Verified, h.Adapter.Enforcement!.State);

        var verify = await h.Adapter.VerifyAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);
        Assert.False(verify.EnforcementVerified);
        Assert.Contains(verify.Notes, note => note.Contains("BPF", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Partial_bpf_map_update_failure_leaves_the_rule_pending_not_applied()
    {
        using var h = new Harness();
        await h.AttachAsync();
        h.Bpftool.FailPrefixes.Add($"bpftool map update pinned {h.BpfPaths.MapPin(BpfLayout.CgroupMap)}");

        var result = await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl", RuleA), CancellationToken.None);

        Assert.NotEqual(RuleState.Applied, result.State);
        Assert.Equal(RuleState.Pending, result.State);
        Assert.NotNull(result.ErrorCode);
        Assert.Contains("BPF", result.ErrorMessage ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        var listed = Assert.Single(await h.Adapter.ListOwnedRulesAsync(CancellationToken.None));
        Assert.NotEqual(RuleState.Applied, listed.State);
        var capabilities = await h.Adapter.GetCapabilitiesAsync(CancellationToken.None);
        Assert.Contains(capabilities.Limitations, limitation => limitation.Contains("BPF", StringComparison.Ordinal) && limitation.Contains("fail", StringComparison.OrdinalIgnoreCase));
    }
}

internal static class BpfTestPaths
{
    public static BpfEnginePaths Create(TempDirectory temp)
    {
        var bpf = Path.Combine(temp.Path, "image", "bpf");
        var bpffs = Path.Combine(temp.Path, "bpffs");
        Directory.CreateDirectory(bpffs);
        Directory.CreateDirectory(bpf);
        var btf = Path.Combine(temp.Path, "vmlinux");
        File.WriteAllText(btf, string.Empty);
        File.WriteAllText(Path.Combine(bpf, BpfEnginePaths.ObjectFileName), string.Empty);
        File.WriteAllText(Path.Combine(bpf, BpfEnginePaths.EventsHelperName), string.Empty);
        return new BpfEnginePaths(
            Path.Combine(bpf, BpfEnginePaths.ObjectFileName),
            Path.Combine(bpf, BpfEnginePaths.EventsHelperName),
            Path.Combine(bpffs, "axiom"),
            Path.Combine(temp.Path, "cgroup"),
            btf,
            bpffs);
    }
}
