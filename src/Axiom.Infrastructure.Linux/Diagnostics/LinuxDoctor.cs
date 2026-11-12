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

    public LinuxDoctor(IProcessRunner runner, LinuxDoctorTargets targets, bool isRoot)
    {
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
        CheckBpfLayer(checks);
        return checks;
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
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "bpf layer", "bpftool is not available; the connect-time layer is off (nftables only, exec-time race window ~1 s)."));
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
            checks.Add(pinned == Bpf.BpfLayout.Programs.Count
                ? new DoctorCheck(DoctorCheck.Pass, "bpf layer", string.Create(CultureInfo.InvariantCulture, $"{version}; {pinned} programs pinned at {pinDirectory} (connect4/connect6/sendmsg4/sendmsg6 at the cgroup root)."))
                : new DoctorCheck(DoctorCheck.Warn, "bpf layer", string.Create(CultureInfo.InvariantCulture, $"{version}; {SystemdServiceInstaller.ServiceTarget} is active but {pinned}/{Bpf.BpfLayout.Programs.Count} programs are pinned at {pinDirectory}; nftables only — `journalctl -u axiomd | grep 'BPF layer'` has the reason.")));
            return;
        }

        checks.Add(pinned > 0 || Directory.Exists(pinDirectory)
            ? new DoctorCheck(DoctorCheck.Warn, "bpf layer", $"{version}; {SystemdServiceInstaller.ServiceTarget} is not active but {pinDirectory} remains; run `sudo axiomd --uninstall-service` or `sudo bpftool cgroup detach / … && sudo rm -r {pinDirectory}`.")
            : new DoctorCheck(DoctorCheck.Pass, "bpf layer", $"{version}; daemon not active, nothing pinned."));
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
