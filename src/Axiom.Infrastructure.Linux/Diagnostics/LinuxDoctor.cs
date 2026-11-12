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
    string ProtectionSettingsPath)
{
    public static LinuxDoctorTargets Default { get; } = new(
        LinuxServicePaths.UnitFilePath,
        LinuxServicePaths.ImageDirectory,
        LinuxServicePaths.Default.MachineDataDirectory,
        LinuxServicePaths.Default.IpcSocketPath,
        LinuxServicePaths.Default.DnsBackupFile,
        ProtectionSettingsStore.DefaultPath);
}

/// <summary>
/// <c>axiomd --doctor [--json]</c> on Linux: unit state and target, image ownership, socket and
/// data-directory modes, resolver backend and per-link DNS, Privacy Shield backup, IPC owner, and
/// the enforcement engine (not available in this build). Exit code 0 when nothing is WARN/FAIL;
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
        CheckDns(checks);
        CheckOwner(checks);
        CheckEnforcement(checks);
        return checks;
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

    private void CheckEnforcement(List<DoctorCheck> checks)
    {
        var nft = _runner.Run("/usr/sbin/nft", ["--version"], ToolTimeout);
        checks.Add(new DoctorCheck(
            DoctorCheck.Warn,
            "enforcement",
            $"firewall enforcement is not available in this build (nftables engine pending); nft {(nft.Succeeded ? nft.StandardOutput.Trim() : "not found")}."));
    }
}
