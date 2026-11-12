// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Infrastructure.MacOS.Diagnostics;
using Axiom.Infrastructure.MacOS.Launchd;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class MacDoctorTests
{
    [Fact]
    public void HealthyInstallPassesEverythingAsRoot()
    {
        using var temp = new TempDirectory();
        var targets = Targets(temp, out var helper, out var data);
        File.WriteAllText(targets.PlistPath, LaunchdServiceInstaller.BuildPlist(Path.Combine(helper, "axiomd"), "/tmp/log"));
        File.SetUnixFileMode(targets.PlistPath, PrivilegedHelperLayout.FileMode);
        var runner = LaunchdServiceInstallerTests.StatAsRoot(new FakeRunner())
            .On("launchctl print", $"\tstate = running\n\tprogram = {helper}/axiomd\n")
            .On("networksetup -listallnetworkservices", "An asterisk (*) denotes that a network service is disabled.\nEthernet\n")
            .On("networksetup -getdnsservers", "There aren't any DNS Servers set on Ethernet.\n")
            .On("systemextensionsctl", "*\t*\t-\tcom.axiom.firewall.filter (1.0.0/10)\tAxiom Firewall Filter\t[activated enabled]\n");
        runner.On("stat -f %u %g %p %N " + targets.IpcSocketPath, $"0 0 140666 {targets.IpcSocketPath}\n");
        runner.On("stat -f %u %g %p %N " + targets.FilterSocketPath, $"0 0 140600 {targets.FilterSocketPath}\n");

        var checks = new MacDoctor(runner, targets, isRoot: true).Collect();

        Assert.All(checks, check => Assert.Equal(DoctorCheck.Pass, check.Status));
        Assert.Contains(checks, check => check.Name == "launchd program" && check.Detail == helper + "/axiomd");
        Assert.Contains(checks, check => check.Name == "plist" && check.Detail.Contains(helper + "/axiomd", StringComparison.Ordinal));
        Assert.Contains(checks, check => check.Name == "helper dir" && check.Detail.Contains("all root-owned", StringComparison.Ordinal));
        Assert.Contains(checks, check => check.Name == "data file" && check.Detail.StartsWith(Path.Combine(data, "axiom.db") + " ", StringComparison.Ordinal));
        Assert.Contains(checks, check => check.Name == "dns" && check.Detail == "'Ethernet' = automatic");
        Assert.Contains(checks, check => check.Name == "dns backup" && check.Detail.StartsWith("none", StringComparison.Ordinal));
        Assert.Contains(checks, check => check.Name == "privacy shield" && check.Detail == "enabled");
        Assert.Contains(checks, check => check.Name == "filter extension" && check.Detail.Contains("[activated enabled]", StringComparison.Ordinal));

        var output = new StringWriter();
        new MacDoctor(runner, targets, isRoot: true).Write(checks, json: true, output);
        using var document = JsonDocument.Parse(output.ToString());
        Assert.True(document.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal(checks.Count, document.RootElement.GetProperty("checks").GetArrayLength());
    }

    [Fact]
    public void ProblemsAreReportedAndRootOnlyChecksSkippedForUsers()
    {
        using var temp = new TempDirectory();
        var targets = Targets(temp, out var helper, out _);
        File.WriteAllText(targets.PlistPath, LaunchdServiceInstaller.BuildPlist("/Applications/Axiom.app/Contents/Resources/service/axiomd", "/tmp/log"));
        var runner = new FakeRunner()
            .On("launchctl print", "Could not find service \"com.axiom.service\" in domain for system\n", exitCode: 113)
            .On("stat", arguments => new ProcessResult(0, string.Join('\n', arguments.Skip(2).Select(path =>
                $"501 20 {(Directory.Exists(path) ? "40755" : "100644")} {path}")), string.Empty))
            .On("networksetup -listallnetworkservices", "An asterisk (*) denotes that a network service is disabled.\nEthernet\n")
            .On("networksetup -getdnsservers", "127.0.0.1\n")
            .On("systemextensionsctl", "no extensions\n");

        var checks = new MacDoctor(runner, targets, isRoot: false).Collect();
        var output = new StringWriter();
        new MacDoctor(runner, targets, isRoot: false).Write(checks, json: false, output);

        Assert.Contains(checks, check => check.Name == "launchd job" && check.Status == DoctorCheck.Fail);
        Assert.Contains(checks, check => check.Name == "plist" && check.Status == DoctorCheck.Fail && check.Detail.Contains("expected " + helper, StringComparison.Ordinal));
        Assert.Contains(checks, check => check.Name == "helper dir" && check.Status == DoctorCheck.Fail && check.Detail.Contains("owned by uid 501", StringComparison.Ordinal));
        Assert.Contains(checks, check => check.Name == "data root" && check.Status == DoctorCheck.Fail);
        Assert.Contains(checks, check => check.Name == "data files" && check.Status == DoctorCheck.Skip);
        Assert.Contains(checks, check => check.Name == "dns" && check.Status == DoctorCheck.Pass && check.Detail.Contains("(Privacy Shield)", StringComparison.Ordinal));
        Assert.Contains(checks, check => check.Name == "dns backup" && check.Status == DoctorCheck.Skip);
        Assert.Contains(checks, check => check.Name == "privacy shield" && check.Status == DoctorCheck.Skip);
        Assert.Contains(checks, check => check.Name == "filter extension" && check.Status == DoctorCheck.Warn);
        Assert.Contains("unprivileged; root-only checks skipped", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("problem(s).", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void LaunchctlAndPlistParsing()
    {
        Assert.Equal("running", MacDoctor.ReadField("system/com.axiom.service = {\n\tstate = running\n\tprogram = /x/axiomd\n}\n", "state"));
        Assert.Null(MacDoctor.ReadField("nothing", "state"));
        Assert.Equal("/opt/A&B/axiomd", MacDoctor.ReadProgramArgument(LaunchdServiceInstaller.BuildPlist("/opt/A&B/axiomd", "/tmp/log")));
        Assert.Null(MacDoctor.ReadProgramArgument("<plist/>"));
    }

    private static DoctorTargets Targets(TempDirectory temp, out string helper, out string data)
    {
        helper = Path.Combine(temp.Path, "PrivilegedHelperTools", "com.axiom.service");
        data = Path.Combine(temp.Path, "Axiom");
        Directory.CreateDirectory(helper);
        Directory.CreateDirectory(Path.Combine(data, "filter"));
        File.WriteAllText(Path.Combine(helper, "axiomd"), "x");
        File.SetUnixFileMode(Path.Combine(helper, "axiomd"), PrivilegedHelperLayout.ExecutableMode);
        File.WriteAllText(Path.Combine(helper, "Axiom.Core.dll"), "x");
        File.SetUnixFileMode(Path.Combine(helper, "Axiom.Core.dll"), PrivilegedHelperLayout.FileMode);
        File.SetUnixFileMode(helper, PrivilegedHelperLayout.DirectoryMode);
        File.WriteAllText(Path.Combine(data, "axiom.db"), "x");
        File.WriteAllText(Path.Combine(data, "filter", "rules.json"), "{}");
        File.WriteAllText(Path.Combine(data, "privacy-shield.json"), "{\"enabled\":true}");
        UnixDataDirectoryPermissions.Enforce(data);
        var plist = Path.Combine(temp.Path, "com.axiom.service.plist");
        return new DoctorTargets(
            plist,
            helper,
            data,
            Path.Combine(temp.Path, "axiom.sock"),
            Path.Combine(temp.Path, "filter.sock"),
            Path.Combine(data, "privacy-shield-dns-backup.json"),
            Path.Combine(data, "protection.json"),
            Path.Combine(data, "privacy-shield.json"));
    }

    [Fact]
    public void DefaultTargetsUseTheProductionLayout()
    {
        var targets = DoctorTargets.Default;

        Assert.Equal("/Library/LaunchDaemons/com.axiom.service.plist", targets.PlistPath);
        Assert.Equal(PrivilegedHelperLayout.HelperDirectory, targets.HelperDirectory);
        Assert.EndsWith("/privacy-shield.json", targets.PrivacyShieldSettingsPath, StringComparison.Ordinal);
        Assert.EndsWith("/protection.json", targets.ProtectionSettingsPath, StringComparison.Ordinal);
        Assert.EndsWith("/privacy-shield-dns-backup.json", targets.DnsBackupPath, StringComparison.Ordinal);
    }
}
