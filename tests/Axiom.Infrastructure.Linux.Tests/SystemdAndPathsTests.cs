// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using System.Text;
using Axiom.Contracts;
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Axiom.Core.Protection;
using Axiom.Infrastructure.Linux.Diagnostics;
using Axiom.Infrastructure.Linux.Systemd;
using Axiom.Infrastructure.Unix.Diagnostics;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Tests;

public sealed class SystemdAndPathsTests
{
    [Fact]
    public void PathsResolveOverridesInOrder()
    {
        Assert.Equal("/run/axiom/axiom.sock", LinuxServicePaths.Resolve("/var/lib/axiom", null, null, null).IpcSocketPath);
        Assert.Equal("/run/axiom", LinuxServicePaths.Resolve("/var/lib/axiom", null, null, null).RunDirectory);
        Assert.Equal("/run/axiom", LinuxServicePaths.Resolve("/var/lib/axiom", null, "/run/axiom:/run/other", null).RunDirectory);
        Assert.Equal("/tmp/r", LinuxServicePaths.Resolve("/var/lib/axiom", "/tmp/r", "/run/axiom", null).RunDirectory);
        Assert.Equal("/tmp/r/axiom.sock", LinuxServicePaths.Resolve("/var/lib/axiom", "/tmp/r", null, null).IpcSocketPath);
        Assert.Equal("/x/s.sock", LinuxServicePaths.Resolve("/var/lib/axiom", "/tmp/r", null, "/x/s.sock").IpcSocketPath);
        Assert.Equal("/var/lib/axiom/filter/managed-rules.json", LinuxServicePaths.Resolve("/var/lib/axiom", null, null, null).ManagedRulesFile);
        Assert.Equal("/usr/libexec/axiom/axiomd", LinuxServicePaths.DaemonPath);
    }

    [Fact]
    public void DataRootOverrideAppliesToUnixOnly()
    {
        Assert.Equal("/tmp/axiom-data", AxiomPaths.MachineDataDirectoryFor(AxiomPlatform.Linux, "/var/lib", "/tmp/axiom-data"));
        Assert.Equal("/var/lib/axiom", AxiomPaths.MachineDataDirectoryFor(AxiomPlatform.Linux, "/var/lib", " "));
        Assert.EndsWith("Axiom", AxiomPaths.MachineDataDirectoryFor(AxiomPlatform.Windows, "C:\\ProgramData", "/tmp/x"), StringComparison.Ordinal);
    }

    [Fact]
    public void UnitTextCarriesTheHardeningAndDirectoriesAndRoundTripsExecStart()
    {
        var unit = SystemdUnit.Build("/usr/libexec/axiom/axiomd", "/var/lib/axiom", "/run/axiom");

        Assert.Contains("Type=notify", unit, StringComparison.Ordinal);
        Assert.Contains("ExecStart=/usr/libexec/axiom/axiomd", unit, StringComparison.Ordinal);
        Assert.Contains("Restart=on-failure", unit, StringComparison.Ordinal);
        Assert.Contains("RuntimeDirectory=axiom", unit, StringComparison.Ordinal);
        Assert.Contains("StateDirectory=axiom", unit, StringComparison.Ordinal);
        Assert.Contains("StateDirectoryMode=0700", unit, StringComparison.Ordinal);
        Assert.Contains("LogsDirectory=axiom", unit, StringComparison.Ordinal);
        Assert.Contains("ProtectSystem=strict", unit, StringComparison.Ordinal);
        Assert.Contains("ReadWritePaths=/var/lib/axiom /run/axiom", unit, StringComparison.Ordinal);

        // PR #276 review, finding 1: resolver paths are optional ("-": a minimal host without
        // NetworkManager or systemd-resolved must not fail with 226/NAMESPACE); Axiom's own state,
        // runtime, cgroup and BPF paths stay required (no "-").
        var readWrite = unit.Split('\n').Single(line => line.StartsWith("ReadWritePaths=", StringComparison.Ordinal))["ReadWritePaths=".Length..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(["/var/lib/axiom", "/run/axiom", "/sys/fs/cgroup", "/sys/fs/bpf", "-/etc/resolv.conf", "-/run/systemd/resolve", "-/run/NetworkManager"], readWrite);
        Assert.Contains(" /sys/fs/bpf ", unit, StringComparison.Ordinal); // BPF pins
        Assert.Contains("ProtectKernelTunables=no", unit, StringComparison.Ordinal); // it would mount /sys/fs/bpf read-only
        Assert.Contains("ReadOnlyPaths=-/proc/sys ", unit, StringComparison.Ordinal);
        Assert.Contains(" -/sys/kernel ", unit, StringComparison.Ordinal);
        Assert.Contains(" CAP_BPF CAP_PERFMON", unit, StringComparison.Ordinal);
        Assert.Contains("NoNewPrivileges=yes", unit, StringComparison.Ordinal);
        Assert.Contains("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN", unit, StringComparison.Ordinal);
        Assert.Contains(" CAP_NET_BIND_SERVICE", unit, StringComparison.Ordinal); // Privacy Shield binds 127.0.0.1:53
        Assert.Contains("Environment=AXIOM_SERVICE=1", unit, StringComparison.Ordinal);
        Assert.Equal("/usr/libexec/axiom/axiomd", SystemdUnit.ReadExecStart(unit));

        var spaced = SystemdUnit.Build("/opt/my app/axiomd", "/var/lib/axiom", "/run/axiom");
        Assert.Contains("ExecStart=\"/opt/my app/axiomd\"", spaced, StringComparison.Ordinal);
        Assert.Equal("/opt/my app/axiomd", SystemdUnit.ReadExecStart(spaced));
    }

    [Fact]
    public void SdNotifySendsReadyOverTheNotifySocket()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var temp = new TempDirectory();
        var path = Path.Combine(temp.Path, "notify.sock");
        using var server = new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
        server.Bind(new UnixDomainSocketEndPoint(path));
        server.ReceiveTimeout = 2000;

        Assert.True(SdNotify.Send(SdNotify.Ready, path));
        var buffer = new byte[64];
        var received = server.Receive(buffer);
        Assert.Equal("READY=1\n", Encoding.UTF8.GetString(buffer, 0, received));

        Assert.False(SdNotify.Send(SdNotify.Ready, null));
        Assert.False(SdNotify.Send(SdNotify.Ready, Path.Combine(temp.Path, "missing.sock")));
        Assert.Equal("\0abstract", SdNotify.AbstractToPath("@abstract"));
    }

    [Fact]
    public void InstallerDryRunPrintsThePlanWithoutRootOrChanges()
    {
        using var temp = new TempDirectory();
        var options = Options(temp);
        var publish = Path.Combine(temp.Path, "publish");
        Directory.CreateDirectory(publish);
        var daemon = Path.Combine(publish, "axiomd");
        File.WriteAllText(daemon, "#!/bin/sh\n");
        var runner = new FakeRunner();
        var installer = new SystemdServiceInstaller(runner, options, () => false, () => 1000, _ => true);
        var output = new StringWriter();
        var error = new StringWriter();

        Assert.Equal(0, installer.Install(daemon, output, error, dryRun: true));

        Assert.Empty(runner.Calls);
        Assert.False(File.Exists(options.UnitPath));
        Assert.False(Directory.Exists(options.ImageDirectory));
        Assert.Contains("[dry-run]", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("Type=notify", output.ToString(), StringComparison.Ordinal);
        Assert.Contains($"ExecStart={options.DaemonPath}", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());

        Assert.Equal(0, installer.Uninstall(output, error, dryRun: true));
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public void InstallerRefusesWithoutRootAndWithoutExecutable()
    {
        using var temp = new TempDirectory();
        var options = Options(temp);
        var error = new StringWriter();
        var installer = new SystemdServiceInstaller(new FakeRunner(), options, () => false, () => null, _ => true);

        Assert.Equal(2, installer.Install(Path.Combine(temp.Path, "missing"), TextWriter.Null, error));
        Assert.Contains("not found", error.ToString(), StringComparison.Ordinal);

        var daemon = Path.Combine(temp.Path, "axiomd");
        File.WriteAllText(daemon, "x");
        Assert.Equal(5, installer.Install(daemon, TextWriter.Null, error));
        Assert.Contains("requires root", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(5, installer.Uninstall(TextWriter.Null, error));
    }

    [Fact]
    public void InstallerCopiesVerifiesWaitsForStopWritesUnitAndStarts()
    {
        using var temp = new TempDirectory();
        var options = Options(temp);
        var publish = Path.Combine(temp.Path, "publish");
        Directory.CreateDirectory(Path.Combine(publish, "lib"));
        var daemon = Path.Combine(publish, "axiomd");
        File.WriteAllText(daemon, "#!/bin/sh\n");
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(daemon, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        }

        File.WriteAllText(Path.Combine(publish, "lib", "Axiom.Core.dll"), "dll");

        var activeChecks = 0;
        var runner = new FakeRunner()
            .On("stat -c", arguments => new ProcessResult(0, string.Join('\n', arguments.Skip(2).Select(path =>
                $"0 0 {(Directory.Exists(path) ? "41ed" : path.EndsWith("axiomd", StringComparison.Ordinal) ? "81ed" : "81a4")} {path}")), string.Empty))
            .On("systemctl is-active", _ => new ProcessResult(++activeChecks < 3 ? 0 : 3, activeChecks < 3 ? "deactivating\n" : "inactive\n", string.Empty))
            .On("systemctl enable --now", _ => new ProcessResult(0, string.Empty, string.Empty));
        var installer = new SystemdServiceInstaller(runner, options, () => true, () => 1000, _ => true);
        var output = new StringWriter();
        var error = new StringWriter();

        Assert.Equal(0, installer.Install(daemon, output, error));

        Assert.Equal(string.Empty, error.ToString());
        Assert.True(File.Exists(options.DaemonPath));
        Assert.True(File.Exists(Path.Combine(options.ImageDirectory, "lib", "Axiom.Core.dll")));
        Assert.True(File.Exists(options.UnitPath));
        Assert.Equal(options.DaemonPath, SystemdUnit.ReadExecStart(File.ReadAllText(options.UnitPath)));
        Assert.Equal(3, activeChecks);
        Assert.Contains(runner.Calls, call => call.StartsWith("chown -R 0:0 ", StringComparison.Ordinal));
        Assert.Contains("systemctl stop axiomd.service", runner.Calls);
        Assert.Contains("systemctl daemon-reload", runner.Calls);
        Assert.Contains("systemctl enable --now axiomd.service", runner.Calls);
        Assert.Equal(1000u, new ProtectionSettingsStore(options.ProtectionSettingsPath).Load().AllowedUid);
        Assert.Contains("Installed and started axiomd.service from", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("uid 1000 (installing user), root and members of the axiom, sudo or wheel groups", output.ToString(), StringComparison.Ordinal);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead, File.GetUnixFileMode(options.UnitPath));
        }

        // Uninstall removes the unit and the image, keeps the data directory.
        Assert.Equal(0, installer.Uninstall(output, error));
        Assert.False(File.Exists(options.UnitPath));
        Assert.False(Directory.Exists(options.ImageDirectory));
        Assert.True(Directory.Exists(options.MachineDataDirectory));
        Assert.Contains("systemctl disable --now axiomd.service", runner.Calls);
    }

    [Fact]
    public void InstallerRefusesANonRootImageAndAHashMismatch()
    {
        using var temp = new TempDirectory();
        var options = Options(temp);
        var publish = Path.Combine(temp.Path, "publish");
        Directory.CreateDirectory(publish);
        var daemon = Path.Combine(publish, "axiomd");
        File.WriteAllText(daemon, "#!/bin/sh\n");

        var runner = new FakeRunner().On("stat -c", arguments => new ProcessResult(0, string.Join('\n', arguments.Skip(2).Select(path =>
            $"1000 1000 {(Directory.Exists(path) ? "41ed" : "81ed")} {path}")), string.Empty));
        var error = new StringWriter();
        var installer = new SystemdServiceInstaller(runner, options, () => true, () => null, _ => true);

        Assert.Equal(3, installer.Install(daemon, TextWriter.Null, error));
        Assert.Contains("not root-owned", error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Directory.GetFileSystemEntries(options.ImageRoot), entry => entry.Contains(".tmp", StringComparison.Ordinal));
    }

    [Fact]
    public void DoctorReportsMissingInstallAndSkipsRootOnlyEnforcementCheck()
    {
        using var temp = new TempDirectory();
        var targets = new LinuxDoctorTargets(
            Path.Combine(temp.Path, "axiomd.service"),
            Path.Combine(temp.Path, "image"),
            Path.Combine(temp.Path, "data"),
            Path.Combine(temp.Path, "run", "axiom.sock"),
            Path.Combine(temp.Path, "data", "backup.json"),
            Path.Combine(temp.Path, "data", "protection.json"));
        var runner = new FakeRunner()
            .On("resolvectl dns", "Global:\nLink 2 (eno2): 192.168.70.1\n")
            .On("nmcli -t -g RUNNING general", "running\n")
            .On("nft --version", "nftables v1.0.9\n")
            .On("stat -c", string.Empty, exitCode: 1);
        var doctor = new LinuxDoctor(runner, targets, isRoot: false);

        var checks = doctor.Collect();
        var output = new StringWriter();
        doctor.Write(checks, json: false, output);

        Assert.Contains(checks, check => check.Name == "systemd unit" && check.Status == DoctorCheck.Warn);
        Assert.Contains(checks, check => check.Name == "protected image" && check.Status == DoctorCheck.Warn);
        Assert.Contains(checks, check => check.Name == "axiom.sock" && check.Status == DoctorCheck.Warn);
        Assert.Contains(checks, check => check.Name == "data directory" && check.Status == DoctorCheck.Skip);
        Assert.Contains(checks, check => check.Name == "dns backend" && check.Status == DoctorCheck.Pass && check.Detail.Contains("192.168.70.1", StringComparison.Ordinal));
        Assert.Contains(checks, check => check.Name == "privacy shield dns" && check.Status == DoctorCheck.Pass);
        Assert.Contains(checks, check => check.Name == "enforcement" && check.Status == DoctorCheck.Skip && check.Detail.Contains("v1.0.9", StringComparison.Ordinal));
        Assert.Contains("unprivileged; root-only checks skipped", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("problem(s).", output.ToString(), StringComparison.Ordinal);
    }

    private static SystemdInstallerOptions Options(TempDirectory temp) => new(
        Path.Combine(temp.Path, "etc", "systemd", "system", "axiomd.service"),
        Path.Combine(temp.Path, "usr", "libexec", "axiom"),
        Path.Combine(temp.Path, "var", "lib", "axiom"),
        Path.Combine(temp.Path, "run", "axiom"),
        Path.Combine(temp.Path, "var", "lib", "axiom", "privacy-shield-dns-backup.json"),
        Path.Combine(temp.Path, "var", "lib", "axiom", "protection.json"))
    {
        LogDirectory = Path.Combine(temp.Path, "var", "log", "axiom"),
    };
}
