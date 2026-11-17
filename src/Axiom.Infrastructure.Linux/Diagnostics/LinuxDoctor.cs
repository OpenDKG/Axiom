// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiom.Core.Protection;
using Axiom.Infrastructure.Linux.Dns;
using Axiom.Infrastructure.Linux.Systemd;
using Axiom.Infrastructure.Unix.Diagnostics;
using Axiom.Infrastructure.Unix.Install;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Diagnostics;

/// <summary>Everything the doctor looks at (production paths by default; tests use a temp root).</summary>
public sealed record LinuxDoctorTargets(
    string UnitPath,
    string ImageDirectory,
    string MachineDataDirectory,
    string IpcSocketPath,
    string DnsBackupPath,
    string ProtectionSettingsPath,
    string? BtfFile = null,
    string? BpfPinDirectory = null)
{
    /// <summary>systemd <c>LogsDirectory=</c>; checked for root 0700 / 0600 files when it exists.</summary>
    public string LogDirectory { get; init; } = LinuxServicePaths.LogDirectory;

    /// <summary>mountinfo read by the "bpf exe key" check (the doctor's own mount namespace).</summary>
    public string MountInfoPath { get; init; } = "/proc/self/mountinfo";

    /// <summary>cgroup root whose attached Axiom programs the "bpf layer" check counts (<c>bpftool cgroup show</c>).</summary>
    public string CgroupRoot { get; init; } = "/sys/fs/cgroup";

    /// <summary>Binary whose BPF exe key the "bpf exe key" check derives.</summary>
    public string ExeKeyProbePath { get; init; } = "/usr/bin/env";

    public static LinuxDoctorTargets Default { get; } = new(
        LinuxServicePaths.UnitFilePath,
        LinuxServicePaths.ImageDirectory,
        LinuxServicePaths.Default.MachineDataDirectory,
        LinuxServicePaths.Default.IpcSocketPath,
        LinuxServicePaths.Default.DnsBackupFile,
        ProtectionSettingsStore.DefaultPath,
        Bpf.BpfEnginePaths.DefaultBtfFile,
        Bpf.BpfEnginePaths.DefaultPinDirectory);
}

/// <summary>
/// What the running daemon reports about its own enforcement (<c>rules.query</c> over the IPC
/// socket): the capability report, or the error that prevented reading it.
/// </summary>
public sealed record DoctorLiveState(Axiom.Contracts.Firewall.FirewallCapabilityReport? Capability, string? Error);

/// <summary>
/// <c>axiomd --doctor [--json]</c> on Linux: unit state and target, image ownership, socket and
/// data-directory modes, resolver backend and per-link DNS, Privacy Shield backup, IPC owner, and
/// the nftables engine (table inet axiom present while the daemon runs). Exit code 0 when nothing is WARN/FAIL;
/// root-only checks are SKIP for a normal user. Pure inspection: nothing is changed.
/// </summary>
public sealed class LinuxDoctor
{
    private static readonly TimeSpan ToolTimeout = TimeSpan.FromSeconds(30);

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly IProcessRunner _runner;

    private readonly LinuxDoctorTargets _targets;

    private readonly bool _isRoot;

    private readonly Func<DoctorLiveState>? _liveState;

    public LinuxDoctor(IProcessRunner runner, LinuxDoctorTargets targets, bool isRoot, Func<DoctorLiveState>? liveState = null)
    {
        _liveState = liveState;
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _targets = targets ?? throw new ArgumentNullException(nameof(targets));
        _isRoot = isRoot;
    }

    public static int Run(string[] args, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(args);
        var json = args.Any(argument => string.Equals(argument, "--json", StringComparison.OrdinalIgnoreCase));
        var doctor = new LinuxDoctor(ProcessRunner.Instance, LinuxDoctorTargets.Default, Environment.IsPrivilegedProcess);
        var checks = doctor.Collect();
        doctor.Write(checks, json, output);
        return checks.Any(check => check.IsProblem) ? 1 : 0;
    }

    public void Write(IReadOnlyList<DoctorCheck> checks, bool json, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(checks);
        ArgumentNullException.ThrowIfNull(output);

        var problems = checks.Count(check => check.IsProblem);
        if (json)
        {
            output.WriteLine(JsonSerializer.Serialize(
                new
                {
                    root = _isRoot,
                    ok = problems == 0,
                    problems,
                    skipped = checks.Count(check => check.Status == DoctorCheck.Skip),
                    checks,
                },
                JsonOptions));
            return;
        }

        output.WriteLine($"axiomd doctor ({(_isRoot ? "root" : "unprivileged; root-only checks skipped")})");
        foreach (var check in checks)
        {
            output.WriteLine(check.ToString());
        }

        output.WriteLine(problems == 0 ? "Result: all checks passed." : $"Result: {problems} problem(s).");
    }

    public IReadOnlyList<DoctorCheck> Collect()
    {
        var checks = new List<DoctorCheck>();
        CheckUnit(checks);
        CheckImage(checks);
        CheckSocket(checks);
        CheckDataDirectory(checks);
        CheckLogDirectory(checks);
        CheckDns(checks);
        CheckOwner(checks);
        CheckEnforcement(checks);
        CheckLiveEnforcement(checks);
        CheckBpfLayer(checks);
        CheckBpfExeKey(checks);
        return checks;
    }

    /// <summary>
    /// "bpf exe key" (docs/LINUX_EBPF.md §3.1): derives the exe-verdict key of a system binary the way
    /// the daemon does — superblock dev from mountinfo field 3, inode from stat — and shows where the
    /// device came from and whether stat's st_dev differs (btrfs subvolume devices). WARN when the key
    /// cannot be proven: exe rules then stay nft-only (with their cgroup key).
    /// </summary>
    private void CheckBpfExeKey(List<DoctorCheck> checks)
    {
        if (!OperatingSystem.IsLinux())
        {
            checks.Add(new DoctorCheck(DoctorCheck.Skip, "bpf exe key", "Linux-only."));
            return;
        }

        var probe = _targets.ExeKeyProbePath;
        var reader = new Bpf.StatInodeReader(_runner, mountInfoPath: _targets.MountInfoPath);
        var stat = reader.Stat(probe);
        var real = stat is null ? null : reader.RealPath(probe);
        if (stat is null || real is null)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "bpf exe key", $"could not stat/realpath {probe}; exe keys are unverified."));
            return;
        }

        var mountInfo = reader.ReadMountInfo();
        var mounts = Bpf.MountInfoTable.Parse(mountInfo);
        var kernel = KernelSelfCheck(reader, mounts);
        var resolution = mountInfo is null
            ? new Bpf.BpfExeKeyResolution(null, $"{_targets.MountInfoPath} is unreadable", null)
            : Bpf.BpfExeKey.Resolve(real, stat, mounts, kernel, reader.SubvolumeId);
        var statDev = string.Create(CultureInfo.InvariantCulture, $"{stat.DevMajor}:{stat.DevMinor}");
        var selfCheck = $" Kernel self-check {kernel.State.ToString().ToLowerInvariant()}: {kernel.Detail}.";
        if (kernel.State == Bpf.BpfKernelKeyState.Mismatch)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "bpf exe key", $"{real}: {kernel.Detail}.{(resolution.Key is { } shown ? " User-space key " + Bpf.BpfKernelKeyCheck.Describe(shown) + "." : string.Empty)}"));
            return;
        }

        if (resolution.Key is null && resolution.Mount is { FsType: "btrfs" })
        {
            // Not a fault, a documented boundary (docs/LINUX_EBPF.md §2.1): the subvolume id is not proven.
            checks.Add(new DoctorCheck(DoctorCheck.Skip, "bpf exe key", $"{real}: {resolution.Detail}; exe rules on btrfs are nft-only (not race-free) plus the herded-cgroup connect-time key.{selfCheck}"));
            return;
        }

        if (resolution.Key is not { } key)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "bpf exe key", $"{real}: {resolution.Detail}; exe rules on such paths are left to nftables (cgroup key only).{selfCheck}"));
            return;
        }

        var subvolume = resolution.Mount is { FsType: "btrfs" }
            ? string.Create(CultureInfo.InvariantCulture, $" + btrfs subvolume id {key.Subvolume} ({resolution.Detail[(resolution.Detail.LastIndexOf(" from ", StringComparison.Ordinal) + 6)..]}); stat st_dev {statDev} is a btrfs subvolume device and is NOT used.")
            : " (subvol 0: not btrfs).";
        checks.Add(new DoctorCheck(DoctorCheck.Pass, "bpf exe key", string.Create(CultureInfo.InvariantCulture, $"{real}: key {Bpf.BpfKernelKeyCheck.Describe(key)}, source mountinfo superblock dev ({resolution.Mount!.FsType} at {resolution.Mount.MountPoint}, {resolution.Mount.Source}){subvolume}{selfCheck}")));
    }

    /// <summary>
    /// Re-checks what the running daemon's program recorded in <c>axiom_selfcheck</c> for the daemon image
    /// against the user-space key of that image (root only; Unverified when the map is not readable).
    /// </summary>
    private Bpf.BpfKernelKeyCheck KernelSelfCheck(Bpf.StatInodeReader reader, Bpf.MountInfoTable mounts)
    {
        if (!_isRoot)
        {
            return Bpf.BpfKernelKeyCheck.Unverified("axiom_selfcheck is readable as root");
        }

        var pin = Path.Combine(_targets.BpfPinDirectory ?? Bpf.BpfEnginePaths.DefaultPinDirectory, "maps", Bpf.BpfLayout.SelfCheckMap);
        var dump = _runner.Run(Bpf.BpfCapabilityProbe.Bpftool, ["-j", "map", "dump", "pinned", pin], ToolTimeout);
        var values = dump.Succeeded ? Bpf.BpfMapDump.Parse(dump.StandardOutput) : null;
        var record = values is not null && values.TryGetValue("00000000", out var hex) ? Bpf.BpfLayout.ParseSelfCheck(hex) : null;
        if (record is null)
        {
            return Bpf.BpfKernelKeyCheck.Unverified($"{pin} is not readable (daemon not running, layer inactive, or an ABI 1 object)");
        }

        var daemon = Path.Combine(_targets.ImageDirectory, ProtectedImageLayout.DaemonFileName);
        var real = reader.RealPath(daemon);
        var stat = real is null ? null : reader.Stat(real);
        return Bpf.BpfKernelKeyCheck.Compare(record with { TargetTgid = 0 }, 0, real ?? daemon, btrfs => real is null || stat is null
            ? new Bpf.BpfExeKeyResolution(null, $"{daemon} could not be resolved/stat'ed", null)
            : Bpf.BpfExeKey.Resolve(real, stat, mounts, new Bpf.BpfKernelKeyCheck(Bpf.BpfKernelKeyState.Verified, btrfs, "doctor"), reader.SubvolumeId));
    }

    /// <summary>
    /// Connect-time BPF layer (docs/LINUX_EBPF.md): WARN (never FAIL — nftables still enforces)
    /// when bpftool, kernel BTF or the shipped object are missing; as root, PASS when the daemon
    /// is active and the programs are pinned, WARN when the daemon is active without pins (see
    /// the journal for the probe reason) or when pins remain after the daemon stopped.
    /// </summary>
    private void CheckBpfLayer(List<DoctorCheck> checks)
    {
        if (!OperatingSystem.IsLinux())
        {
            checks.Add(new DoctorCheck(DoctorCheck.Skip, "bpf layer", "Linux-only."));
            return;
        }

        var bpftool = _runner.Run(Bpf.BpfCapabilityProbe.Bpftool, ["version"], ToolTimeout);
        if (!bpftool.Succeeded)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "bpf layer", $"bpftool is not available ({Bpf.BpftoolHint.Current()}); the connect-time layer is off (nftables only, exec-time race window ~1 s)."));
            return;
        }

        var version = bpftool.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() ?? "bpftool";
        var btf = _targets.BtfFile ?? Bpf.BpfEnginePaths.DefaultBtfFile;
        if (!File.Exists(btf))
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "bpf layer", $"{version}; {btf} is missing (kernel without BTF); the connect-time layer is off."));
            return;
        }

        var objectFile = Path.Combine(_targets.ImageDirectory, "bpf", Bpf.BpfEnginePaths.ObjectFileName);
        if (!File.Exists(objectFile))
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "bpf layer", $"{version}; {objectFile} is not shipped (build Bpf/native with clang + libbpf-dev); the connect-time layer is off."));
            return;
        }

        var pinDirectory = _targets.BpfPinDirectory ?? Bpf.BpfEnginePaths.DefaultPinDirectory;
        if (!_isRoot)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Skip, "bpf layer", $"{version}; {pinDirectory} is readable as root."));
            return;
        }

        var active = string.Equals(
            _runner.Run(SystemdServiceInstaller.Systemctl, ["is-active", SystemdServiceInstaller.ServiceTarget], ToolTimeout).StandardOutput.Trim(),
            "active",
            StringComparison.Ordinal);
        var pinned = Bpf.BpfLayout.Programs.Count(program => File.Exists(Path.Combine(pinDirectory, program.Program)));
        if (active)
        {
            // #290: pin files prove nothing about the running layer (a previous daemon's stale pins look
            // identical). The verdict comes from the daemon's own live state over IPC.
            checks.Add(BpfLayerFromLiveState(version, pinned, pinDirectory));
            return;
        }

        checks.Add(pinned > 0 || Directory.Exists(pinDirectory)
            ? new DoctorCheck(DoctorCheck.Warn, "bpf layer", $"{version}; {SystemdServiceInstaller.ServiceTarget} is not active but {pinDirectory} remains; run `sudo axiomd --uninstall-service` or `sudo bpftool cgroup detach / … && sudo rm -r {pinDirectory}`.")
            : new DoctorCheck(DoctorCheck.Pass, "bpf layer", $"{version}; daemon not active, nothing pinned."));
    }

    private DoctorLiveState? _live;

    /// <summary>The daemon's live enforcement state (<c>rules.query</c>), queried once per run.</summary>
    private DoctorLiveState LiveState() => _live ??= (_liveState ?? QueryLiveState)();

    private DoctorLiveState QueryLiveState()
    {
        try
        {
            var client = new Axiom.Contracts.Ipc.IpcPipeClient(_targets.IpcSocketPath, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(10));
            var snapshot = Task.Run(() => client.SendAsync<Axiom.Contracts.Ipc.FirewallRulesSnapshot>(Axiom.Contracts.Ipc.IpcCommandTypes.RulesQuery, null, CancellationToken.None)).GetAwaiter().GetResult();
            return snapshot?.Capability is { } capability
                ? new DoctorLiveState(capability, null)
                : new DoctorLiveState(null, "rules.query returned no capability report");
        }
        catch (Exception exception) when (exception is Axiom.Contracts.Ipc.IpcClientException or IOException or TimeoutException or OperationCanceledException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            return new DoctorLiveState(null, exception.Message);
        }
    }

    /// <summary>
    /// Axiom programs attached at the cgroup root as the kernel reports them (<c>bpftool -j cgroup show</c>),
    /// or null when that cannot be read (PR #276 review, finding 4: pins and the daemon's belief alone
    /// missed 16–44 attached programs).
    /// </summary>
    private int? KernelAttachedAxiomPrograms(out string unreadable)
    {
        var show = _runner.Run(Bpf.BpfCapabilityProbe.Bpftool, ["-j", "cgroup", "show", _targets.CgroupRoot], ToolTimeout);
        if (!show.Succeeded)
        {
            unreadable = string.Create(CultureInfo.InvariantCulture, $"bpftool cgroup show {_targets.CgroupRoot} exited {show.ExitCode}");
            return null;
        }

        if (Bpf.BpfMapDump.ParseAttached(show.StandardOutput) is not { } attached)
        {
            unreadable = $"bpftool cgroup show {_targets.CgroupRoot} printed unreadable output";
            return null;
        }

        unreadable = string.Empty;
        var names = Bpf.BpfLayout.Programs.Select(program => program.Program).ToHashSet(StringComparer.Ordinal);
        return attached.Count(program => names.Contains(program.Name));
    }

    private DoctorCheck BpfLayerFromLiveState(string version, int pinned, string pinDirectory)
    {
        var expected = Bpf.BpfLayout.Programs.Count;
        var kernel = KernelAttachedAxiomPrograms(out var unreadable);
        var kernelText = kernel is { } count
            ? string.Create(CultureInfo.InvariantCulture, $"{count} Axiom program(s) attached at {_targets.CgroupRoot}")
            : $"cannot confirm how many Axiom programs are attached at {_targets.CgroupRoot} ({unreadable})";
        var pins = string.Create(CultureInfo.InvariantCulture, $"{kernelText}; {pinned}/{expected} program pins at {pinDirectory}{(kernel is null ? " (pin files alone do not prove the layer is attached)" : string.Empty)}");
        var live = LiveState();
        if (live.Capability is not { } capability)
        {
            return new DoctorCheck(DoctorCheck.Warn, "bpf layer", $"{version}; cannot confirm live state: the daemon's rules.query over {_targets.IpcSocketPath} failed ({live.Error ?? "no reply"}); {pins} (pin files alone do not prove the layer is attached or healthy).");
        }

        if (capability.ConnectTimeLayer is not { } layer)
        {
            return new DoctorCheck(DoctorCheck.Warn, "bpf layer", $"{version}; cannot confirm live state: the daemon did not report its connect-time layer (older axiomd?); {pins}.");
        }

        var problems = new List<string>();
        if (kernel is null)
        {
            problems.Add("cannot confirm the attachment state: " + unreadable);
        }

        if (string.Equals(layer.State, "unknown", StringComparison.Ordinal))
        {
            problems.Add($"the daemon cannot confirm whether its programs are attached ({layer.Status})");
        }
        else if (!string.Equals(layer.State, "active", StringComparison.Ordinal))
        {
            problems.Add($"live layer {layer.State} ({layer.Status})");
        }

        if (kernel is { } attachedNow && string.Equals(layer.State, "active", StringComparison.Ordinal) && attachedNow != expected)
        {
            problems.Add(string.Create(CultureInfo.InvariantCulture, $"the daemon reports an active layer but the kernel has {attachedNow} Axiom program(s) attached (one set is {expected})"));
        }

        if (layer.PendingRemovals.Count > 0)
        {
            problems.Add(string.Create(CultureInfo.InvariantCulture, $"{layer.PendingRemovals.Count} rule removal(s) with unconfirmed BPF cleanup: {string.Join(", ", layer.PendingRemovals.Select(id => id.ToString("D", CultureInfo.InvariantCulture)))}"));
        }

        if (layer.FailedDeletes.Count > 0)
        {
            problems.Add($"failed map deletes: {string.Join("; ", layer.FailedDeletes)}");
        }

        if (layer.FailedUpdates.Count > 0)
        {
            problems.Add($"failed map updates: {string.Join("; ", layer.FailedUpdates)}");
        }

        if (string.Equals(layer.State, "active", StringComparison.Ordinal) && pinned != Bpf.BpfLayout.Programs.Count)
        {
            problems.Add("the daemon reports an active layer but " + pins);
        }

        if (problems.Count > 0 || !layer.Healthy)
        {
            return new DoctorCheck(DoctorCheck.Warn, "bpf layer", $"{version}; {(problems.Count > 0 ? string.Join("; ", problems) : $"live layer {layer.State} not healthy ({layer.Status})")}; {pins}. `journalctl -u axiomd | grep 'BPF layer'` has the detail.");
        }

        return new DoctorCheck(DoctorCheck.Pass, "bpf layer", string.Create(CultureInfo.InvariantCulture, $"{version}; live layer active, generation {layer.Generation?.ToString(CultureInfo.InvariantCulture) ?? "none"}, maps {(layer.MapsVerified ? "read back verified" : "not synced yet")}; {layer.ConnectTimeProvenRules.Count} rule(s) connect-time proven, {layer.NftOnlyRules.Count} rule(s) nft-only (not race-free); {pins}."));
    }

    /// <summary>
    /// "live enforcement": the daemon's own capability status (rules.query) while it is active, so a
    /// degraded table/layer or an unconfirmed removal is never summarised as "all checks passed".
    /// </summary>
    private void CheckLiveEnforcement(List<DoctorCheck> checks)
    {
        if (!OperatingSystem.IsLinux() || !_isRoot)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Skip, "live enforcement", "queried over IPC as root."));
            return;
        }

        var active = string.Equals(
            _runner.Run(SystemdServiceInstaller.Systemctl, ["is-active", SystemdServiceInstaller.ServiceTarget], ToolTimeout).StandardOutput.Trim(),
            "active",
            StringComparison.Ordinal);
        if (!active)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Skip, "live enforcement", $"{SystemdServiceInstaller.ServiceTarget} is not active."));
            return;
        }

        var live = LiveState();
        if (live.Capability is not { } capability)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "live enforcement", $"cannot confirm live state: rules.query failed ({live.Error ?? "no reply"})."));
            return;
        }

        var state = capability.FilterEnforcement?.State.ToString().ToLowerInvariant() ?? "unreported";

        // A neutralised/degraded connect-time layer is a live enforcement problem even while the nft table
        // is fine: new processes get the ~1 s exec-time window again (the "bpf layer" line has the detail).
        if (capability.ConnectTimeLayer is { State: "neutralised" or "degraded" or "stale_programs" } layer)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "live enforcement", $"capability {capability.Status.ToString().ToLowerInvariant()}, enforcement {state}, but the connect-time BPF layer is {layer.State} ({layer.Status}); nftables only, not race-free{(capability.Reason is { Length: > 0 } reason ? "; " + reason : string.Empty)}"));
            return;
        }

        // Starting (docs/LINUX_EBPF.md §11): a new program set is attached next to a previous daemon's set
        // and not populated and read back yet. Not a fault, but nothing connect-time is verified.
        if (capability.ConnectTimeLayer is { State: "pending" } starting)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "live enforcement", $"capability {capability.Status.ToString().ToLowerInvariant()}, enforcement {state}: the connect-time BPF layer is pending ({starting.Status}); connect-time blocking is not verified yet. Run --doctor again in a few seconds."));
            return;
        }

        checks.Add(capability.Status == Axiom.Contracts.Firewall.FirewallCapabilityStatus.Available && capability.FilterEnforcement?.State is not (Axiom.Contracts.Firewall.FilterEnforcementState.Degraded or Axiom.Contracts.Firewall.FilterEnforcementState.Unavailable)
            ? new DoctorCheck(DoctorCheck.Pass, "live enforcement", $"capability available, enforcement {state}{(capability.Reason is { Length: > 0 } note ? "; " + note : string.Empty)}")
            : new DoctorCheck(DoctorCheck.Warn, "live enforcement", $"capability {capability.Status.ToString().ToLowerInvariant()}, enforcement {state}: {capability.Reason ?? "no reason given"}"));
    }

    private void CheckUnit(List<DoctorCheck> checks)
    {
        if (!File.Exists(_targets.UnitPath))
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "systemd unit", $"{_targets.UnitPath} is missing; run `sudo axiomd --install-service`."));
            return;
        }

        var execStart = SystemdUnit.ReadExecStart(File.ReadAllText(_targets.UnitPath));
        var expected = Path.Combine(_targets.ImageDirectory, ProtectedImageLayout.DaemonFileName);
        checks.Add(string.Equals(execStart, expected, StringComparison.Ordinal)
            ? new DoctorCheck(DoctorCheck.Pass, "systemd unit", $"{_targets.UnitPath} starts {expected}.")
            : new DoctorCheck(DoctorCheck.Fail, "systemd unit", $"ExecStart is '{execStart}', expected {expected}."));

        var active = _runner.Run(SystemdServiceInstaller.Systemctl, ["is-active", SystemdServiceInstaller.ServiceTarget], ToolTimeout).StandardOutput.Trim();
        var enabled = _runner.Run(SystemdServiceInstaller.Systemctl, ["is-enabled", SystemdServiceInstaller.ServiceTarget], ToolTimeout).StandardOutput.Trim();
        checks.Add(string.Equals(active, "active", StringComparison.Ordinal)
            ? new DoctorCheck(DoctorCheck.Pass, "service state", $"{SystemdServiceInstaller.ServiceTarget} is active ({enabled}).")
            : new DoctorCheck(DoctorCheck.Warn, "service state", $"{SystemdServiceInstaller.ServiceTarget} is {(active.Length == 0 ? "unknown" : active)} ({(enabled.Length == 0 ? "not enabled" : enabled)})."));
    }

    private void CheckImage(List<DoctorCheck> checks)
    {
        if (!Directory.Exists(_targets.ImageDirectory))
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "protected image", $"{_targets.ImageDirectory} does not exist."));
            return;
        }

        var paths = ProtectedImageLayout.EnumerateTree(_targets.ImageDirectory);
        var entries = UnixFileStat.List(_runner, paths, StatFlavor.Gnu);
        var problems = ProtectedImageLayout.Audit(_targets.ImageDirectory, entries);
        checks.Add(problems.Count == 0
            ? new DoctorCheck(DoctorCheck.Pass, "protected image", $"{_targets.ImageDirectory}: {entries.Count.ToString(CultureInfo.InvariantCulture)} entries root-owned and read-only.")
            : new DoctorCheck(DoctorCheck.Fail, "protected image", string.Join(" ", problems)));
    }

    private void CheckSocket(List<DoctorCheck> checks)
    {
        var entry = UnixFileStat.Stat(_runner, _targets.IpcSocketPath, StatFlavor.Gnu);
        if (entry is null)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "axiom.sock", $"{_targets.IpcSocketPath} is missing (daemon not running?)."));
            return;
        }

        checks.Add(entry.IsRootOwned && entry.Permissions == 0x1B6
            ? new DoctorCheck(DoctorCheck.Pass, "axiom.sock", $"{_targets.IpcSocketPath} root 0666 (peer uid checked with SO_PEERCRED).")
            : new DoctorCheck(DoctorCheck.Warn, "axiom.sock", $"{_targets.IpcSocketPath} is {entry.Describe()}, expected root 0666."));
    }

    private void CheckDataDirectory(List<DoctorCheck> checks)
    {
        if (!_isRoot)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Skip, "data directory", $"{_targets.MachineDataDirectory} modes are checked as root."));
            return;
        }

        var entry = UnixFileStat.Stat(_runner, _targets.MachineDataDirectory, StatFlavor.Gnu);
        checks.Add(entry is null
            ? new DoctorCheck(DoctorCheck.Warn, "data directory", $"{_targets.MachineDataDirectory} does not exist.")
            : entry.IsRootOwned && entry.Permissions == 0x1C0
                ? new DoctorCheck(DoctorCheck.Pass, "data directory", $"{_targets.MachineDataDirectory} root 0700.")
                : new DoctorCheck(DoctorCheck.Fail, "data directory", $"{_targets.MachineDataDirectory} is {entry.Describe()}, expected root 0700."));
    }

    /// <summary>
    /// Daemon logs go to the journal (readable by root and the adm/systemd-journal groups under
    /// systemd's policy); <c>/var/log/axiom</c> exists for file logs and must be root 0700 with
    /// 0600 files so a second local user cannot read process names, paths and rule ids.
    /// </summary>
    private void CheckLogDirectory(List<DoctorCheck> checks)
    {
        if (!_isRoot)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Skip, "log directory", $"{_targets.LogDirectory} modes are checked as root."));
            return;
        }

        var entry = UnixFileStat.Stat(_runner, _targets.LogDirectory, StatFlavor.Gnu);
        if (entry is null)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Pass, "log directory", $"{_targets.LogDirectory} does not exist; daemon logs go to the journal only."));
            return;
        }

        if (!entry.IsRootOwned || entry.Permissions != 0x1C0)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "log directory", $"{_targets.LogDirectory} is {entry.Describe()}, expected root 0700; the daemon tightens it at start."));
            return;
        }

        var files = Directory.Exists(_targets.LogDirectory) ? Directory.EnumerateFiles(_targets.LogDirectory).ToList() : [];
        var loose = UnixFileStat.List(_runner, files, StatFlavor.Gnu).Where(file => !file.IsRootOwned || file.Permissions != 0x180).Select(file => file.Path).ToList();
        checks.Add(loose.Count == 0
            ? new DoctorCheck(DoctorCheck.Pass, "log directory", $"{_targets.LogDirectory} root 0700{(files.Count == 0 ? ", no file logs (journal only)" : $", {files.Count.ToString(CultureInfo.InvariantCulture)} file(s) 0600")}.")
            : new DoctorCheck(DoctorCheck.Warn, "log directory", $"{_targets.LogDirectory}: not root 0600: {string.Join(", ", loose)}."));
    }

    private void CheckDns(List<DoctorCheck> checks)
    {
        var kind = LinuxDnsBackendDetector.Detect(_runner);
        var backend = LinuxDnsBackendDetector.Create(kind, _runner);
        var links = backend.ListLinks();
        var redirected = links.Where(link => LinuxDnsConfigurator.IsLoopbackOnly(link.Servers)).Select(link => link.Name).ToList();
        var summary = string.Join("; ", links.Select(link => $"{link.Name}: {(link.Servers.Count == 0 ? "automatic" : string.Join(' ', link.Servers))}"));
        checks.Add(new DoctorCheck(DoctorCheck.Pass, "dns backend", $"{kind}; {(links.Count == 0 ? "no links with resolver configuration" : summary)}"));

        var hasBackup = File.Exists(_targets.DnsBackupPath);
        if (redirected.Count > 0)
        {
            checks.Add(hasBackup
                ? new DoctorCheck(DoctorCheck.Pass, "privacy shield dns", $"redirected to 127.0.0.1 on {string.Join(", ", redirected)}; backup present.")
                : new DoctorCheck(DoctorCheck.Fail, "privacy shield dns", $"{string.Join(", ", redirected)} point only at loopback but {_targets.DnsBackupPath} is missing; run `sudo axiomd --recover-network`."));
        }
        else
        {
            checks.Add(hasBackup
                ? new DoctorCheck(DoctorCheck.Warn, "privacy shield dns", $"no link is redirected but {_targets.DnsBackupPath} still exists (stale backup).")
                : new DoctorCheck(DoctorCheck.Pass, "privacy shield dns", "not redirected; no backup."));
        }
    }

    private void CheckOwner(List<DoctorCheck> checks)
    {
        if (!_isRoot)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Skip, "ipc owner", $"{_targets.ProtectionSettingsPath} is readable as root."));
            return;
        }

        var settings = new ProtectionSettingsStore(_targets.ProtectionSettingsPath).Load();
        checks.Add(settings.AllowedUid is { } uid
            ? new DoctorCheck(DoctorCheck.Pass, "ipc owner", $"uid {uid.ToString(CultureInfo.InvariantCulture)} may write; admin groups {(settings.AllowAdminGroupWrites ? "allowed" : "read-only")}.")
            : new DoctorCheck(DoctorCheck.Warn, "ipc owner", "no installing user recorded; only root (and admin groups when enabled) may write."));
    }

    /// <summary>
    /// nftables engine: <c>nft</c> must exist; while the daemon is active <c>table inet axiom</c>
    /// must be present (the daemon publishes it at start and republishes when it vanishes), and
    /// when the daemon is not running a leftover table or <c>axiom.slice</c> is a problem.
    /// </summary>
    private void CheckEnforcement(List<DoctorCheck> checks)
    {
        if (!OperatingSystem.IsLinux())
        {
            checks.Add(new DoctorCheck(DoctorCheck.Skip, "enforcement", "nftables is Linux-only."));
            return;
        }

        var nft = _runner.Run(Nft.NftProcessRunner.DefaultBinary, ["--version"], ToolTimeout);
        if (!nft.Succeeded)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Fail, "enforcement", $"{Nft.NftProcessRunner.DefaultBinary} is not available; install the nftables package."));
            return;
        }

        var version = nft.StandardOutput.Trim();
        if (!_isRoot)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Skip, "enforcement", $"{version}; table inet axiom is readable as root."));
            return;
        }

        var active = string.Equals(
            _runner.Run(SystemdServiceInstaller.Systemctl, ["is-active", SystemdServiceInstaller.ServiceTarget], ToolTimeout).StandardOutput.Trim(),
            "active",
            StringComparison.Ordinal);
        var list = _runner.Run(Nft.NftProcessRunner.DefaultBinary, ["-j", "list", "table", "inet", Nft.NftRuleCompiler.TableName], ToolTimeout);
        var generation = list.Succeeded ? Nft.NftTable.ParseGeneration(list.StandardOutput) : null;
        var sliceExists = Directory.Exists(Path.Combine(Nft.ProcCgroupFs.DefaultCgroupRoot, Nft.AppCgroupManager.DefaultSlice));
        if (active)
        {
            checks.Add(generation is { } live
                ? new DoctorCheck(DoctorCheck.Pass, "enforcement", string.Create(CultureInfo.InvariantCulture, $"{version}; table inet axiom generation {live} is in force{(sliceExists ? ", axiom.slice present" : string.Empty)}."))
                : new DoctorCheck(DoctorCheck.Fail, "enforcement", $"{version}; {SystemdServiceInstaller.ServiceTarget} is active but table inet axiom is {(list.Succeeded ? "foreign (no Axiom generation comment)" : "missing")}; the daemon republishes within 10 s — if it stays missing check `journalctl -u axiomd`."));
            return;
        }

        checks.Add(list.Succeeded || sliceExists
            ? new DoctorCheck(DoctorCheck.Warn, "enforcement", $"{version}; {SystemdServiceInstaller.ServiceTarget} is not active but {(list.Succeeded ? "table inet axiom" : string.Empty)}{(list.Succeeded && sliceExists ? " and " : string.Empty)}{(sliceExists ? "/sys/fs/cgroup/axiom.slice" : string.Empty)} remain(s); run `sudo nft delete table inet axiom` / `sudo axiomd --uninstall-service`.")
            : new DoctorCheck(DoctorCheck.Pass, "enforcement", $"{version}; daemon not active, no table inet axiom, no axiom.slice."));
    }
}
