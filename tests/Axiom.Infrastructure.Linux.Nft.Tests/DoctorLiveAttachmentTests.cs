// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Bpf;
using Axiom.Infrastructure.Linux.Diagnostics;
using Axiom.Infrastructure.Unix.Diagnostics;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

/// <summary>
/// PR #276 review (brxtrac), finding 4: <c>--doctor</c> printed "4/4 program pins" (or 0/4) while 16–44
/// Axiom programs were attached. The doctor now counts the Axiom programs attached at the cgroup root
/// itself and says it cannot confirm the state when that count cannot be read.
/// </summary>
public sealed class DoctorLiveAttachmentTests
{
    private static readonly FirewallCapabilityReport HealthyActive = new()
    {
        Status = FirewallCapabilityStatus.Available,
        ConnectTimeLayer = new ConnectTimeLayerReport { State = "active", Healthy = true, Attached = true, Generation = 3, MapsVerified = true },
    };

    private static (LinuxDoctor Doctor, FakeBpftool Bpftool, TempDirectory Temp) Fixture(FirewallCapabilityReport live)
    {
        var temp = new TempDirectory();
        var image = Path.Combine(temp.Path, "image");
        Directory.CreateDirectory(Path.Combine(image, "bpf"));
        File.WriteAllText(Path.Combine(image, "bpf", BpfEnginePaths.ObjectFileName), string.Empty);
        var btf = Path.Combine(temp.Path, "vmlinux");
        File.WriteAllText(btf, string.Empty);
        var pins = Path.Combine(temp.Path, "pins");
        Directory.CreateDirectory(pins);
        foreach (var (_, program) in BpfLayout.Programs)
        {
            File.WriteAllText(Path.Combine(pins, program), string.Empty);
        }

        var targets = new LinuxDoctorTargets(
            Path.Combine(temp.Path, "axiomd.service"),
            image,
            Path.Combine(temp.Path, "data"),
            Path.Combine(temp.Path, "axiom.sock"),
            Path.Combine(temp.Path, "backup.json"),
            Path.Combine(temp.Path, "protection.json"),
            btf,
            pins);
        var bpftool = new FakeBpftool(pins);
        return (new LinuxDoctor(new LiveStateAndCoverageTests.ActiveUnitRunner(bpftool), targets, isRoot: true, () => new DoctorLiveState(live, null)), bpftool, temp);
    }

    private static void AttachSets(FakeBpftool bpftool, int sets)
    {
        var id = 500L;
        for (var set = 0; set < sets; set++)
        {
            foreach (var (hook, program) in BpfLayout.Programs)
            {
                bpftool.Attached[id++] = (program, hook);
            }
        }
    }

    [Fact]
    public void Doctor_passes_with_one_attached_set_and_reports_the_kernel_count()
    {
        var (doctor, bpftool, temp) = Fixture(HealthyActive);
        using var _ = temp;
        AttachSets(bpftool, 1);

        var bpf = doctor.Collect().Single(check => check.Name == "bpf layer");

        Assert.Equal(DoctorCheck.Pass, bpf.Status);
        Assert.Contains("4 Axiom program(s) attached", bpf.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Doctor_warns_when_more_than_one_program_set_is_attached_although_four_pins_exist()
    {
        var (doctor, bpftool, temp) = Fixture(HealthyActive);
        using var _ = temp;
        AttachSets(bpftool, 4);

        var bpf = doctor.Collect().Single(check => check.Name == "bpf layer");

        Assert.Equal(DoctorCheck.Warn, bpf.Status);
        Assert.Contains("16 Axiom program(s) attached", bpf.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("shim: <<not json>> {")]
    [InlineData("exit1")]
    public void Doctor_says_it_cannot_confirm_when_cgroup_show_is_unreadable(string fault)
    {
        var (doctor, bpftool, temp) = Fixture(HealthyActive);
        using var _ = temp;
        AttachSets(bpftool, 1);
        if (fault == "exit1")
        {
            bpftool.FailPrefixes.Add("bpftool -j cgroup show");
        }
        else
        {
            bpftool.CgroupShowOutput = fault;
        }

        var bpf = doctor.Collect().Single(check => check.Name == "bpf layer");

        Assert.Equal(DoctorCheck.Warn, bpf.Status);
        Assert.Contains("cannot confirm", bpf.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("live layer active", bpf.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Doctor_reports_an_unknown_daemon_layer_as_unconfirmed_not_as_a_pin_count()
    {
        var unknown = new FirewallCapabilityReport
        {
            Status = FirewallCapabilityStatus.Degraded,
            ConnectTimeLayer = new ConnectTimeLayerReport { State = "unknown", Healthy = false, Attached = true, Status = "unknown: the daemon cannot confirm whether its BPF programs are attached" },
        };
        var (doctor, bpftool, temp) = Fixture(unknown);
        using var _ = temp;
        AttachSets(bpftool, 1);

        var bpf = doctor.Collect().Single(check => check.Name == "bpf layer");

        Assert.Equal(DoctorCheck.Warn, bpf.Status);
        Assert.Contains("cannot confirm", bpf.Detail, StringComparison.Ordinal);
        Assert.Contains("4 Axiom program(s) attached", bpf.Detail, StringComparison.Ordinal);
    }
}
