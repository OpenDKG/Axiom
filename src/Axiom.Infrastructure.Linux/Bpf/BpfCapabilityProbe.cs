// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Bpf;

/// <summary>Where the layer's files live; production values come from <see cref="Default"/>.</summary>
public sealed record BpfEnginePaths(
    string ObjectFile,
    string EventsHelper,
    string PinDirectory,
    string CgroupRoot,
    string BtfFile,
    string BpfFs)
{
    public const string DefaultPinDirectory = "/sys/fs/bpf/axiom";
    public const string DefaultCgroupRoot = "/sys/fs/cgroup";
    public const string DefaultBtfFile = "/sys/kernel/btf/vmlinux";
    public const string DefaultBpfFs = "/sys/fs/bpf";
    public const string ObjectFileName = "axiom_connect.bpf.o";
    public const string EventsHelperName = "axiom-bpf-events";

    /// <summary>The objects ship next to the daemon under <c>bpf/</c> (<c>/usr/libexec/axiom/bpf</c> once installed).</summary>
    public static BpfEnginePaths Default { get; } = ForImage(AppContext.BaseDirectory);

    public static BpfEnginePaths ForImage(string imageDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(imageDirectory);
        var bpf = Path.Combine(imageDirectory, "bpf");
        return new BpfEnginePaths(
            Path.Combine(bpf, ObjectFileName),
            Path.Combine(bpf, EventsHelperName),
            DefaultPinDirectory,
            DefaultCgroupRoot,
            DefaultBtfFile,
            DefaultBpfFs);
    }

    public string MapDirectory => Path.Combine(PinDirectory, "maps");

    public string MapPin(string map) => Path.Combine(MapDirectory, map);

    public string ProgramPin(string program) => Path.Combine(PinDirectory, program);
}

public sealed record BpfProbeResult(bool Usable, string Reason, string? BpftoolVersion)
{
    public static BpfProbeResult Ok(string version) => new(true, "ready", version);
}

/// <summary>
/// Decides whether the connect-time layer can run here, in the order a reader of the journal
/// expects: root (bpf() is root-only with <c>unprivileged_bpf_disabled=2</c>), shipped objects,
/// <c>bpftool</c>, kernel BTF (CO-RE), bpffs. Every "no" degrades the daemon to nft-only with the
/// reason in <see cref="BpfProbeResult.Reason"/>; nothing is installed or mounted by the probe.
/// </summary>
public static class BpfCapabilityProbe
{
    public const string Bpftool = "bpftool";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    public static BpfProbeResult Probe(IProcessRunner runner, BpfEnginePaths paths, bool privileged, Func<string, bool>? fileExists = null, Func<string, bool>? directoryExists = null)
    {
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(paths);
        var exists = fileExists ?? File.Exists;
        var dirExists = directoryExists ?? Directory.Exists;

        if (!privileged)
        {
            return new BpfProbeResult(false, "not root (bpf() needs CAP_BPF/CAP_SYS_ADMIN; unprivileged_bpf_disabled is 2 on Ubuntu)", null);
        }

        if (!exists(paths.ObjectFile))
        {
            return new BpfProbeResult(false, $"BPF object not shipped: {paths.ObjectFile} (build src/Axiom.Infrastructure.Linux/Bpf/native with clang + libbpf-dev)", null);
        }

        if (!exists(paths.EventsHelper))
        {
            return new BpfProbeResult(false, $"event helper not shipped: {paths.EventsHelper}", null);
        }

        var version = runner.Run(Bpftool, ["version"], Timeout);
        if (!version.Succeeded)
        {
            return new BpfProbeResult(false, $"bpftool is not available ({BpftoolHint.Current()})", null);
        }

        var versionText = version.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() ?? "bpftool";
        if (!exists(paths.BtfFile))
        {
            return new BpfProbeResult(false, $"kernel has no BTF ({paths.BtfFile} missing); CO-RE exe lookup cannot be relocated", versionText);
        }

        if (!dirExists(paths.BpfFs))
        {
            return new BpfProbeResult(false, $"bpffs is not mounted at {paths.BpfFs}", versionText);
        }

        return BpfProbeResult.Ok(versionText);
    }
}
