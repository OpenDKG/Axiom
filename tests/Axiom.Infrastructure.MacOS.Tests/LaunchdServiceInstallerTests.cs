// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Protection;
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Infrastructure.MacOS.Launchd;
using Axiom.Infrastructure.MacOS.ProcessIdentity;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class LaunchdServiceInstallerTests
{
    [Fact]
    public void PlistDefinesTheDaemonJob()
    {
        var text = LaunchdServiceInstaller.BuildPlist(PrivilegedHelperLayout.DaemonPath, "/Library/Logs/Axiom/axiomd.log");

        Assert.StartsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", text, StringComparison.Ordinal);
        var values = MacBundleInfo.ParseXmlPlist(text);
        Assert.NotNull(values);
        Assert.Equal("com.axiom.service", values["Label"]);
        Assert.Equal("/Library/PrivilegedHelperTools/com.axiom.service", values["WorkingDirectory"]);
        Assert.Equal("Interactive", values["ProcessType"]);
        Assert.Equal("/Library/Logs/Axiom/axiomd.log", values["StandardOutPath"]);
        Assert.Equal("/Library/Logs/Axiom/axiomd.log", values["StandardErrorPath"]);
        Assert.Contains("<string>/Library/PrivilegedHelperTools/com.axiom.service/axiomd</string>", text, StringComparison.Ordinal);
        Assert.Contains("<key>RunAtLoad</key>\n    <true/>", text, StringComparison.Ordinal);
        Assert.Contains("<key>KeepAlive</key>\n    <dict>\n        <key>SuccessfulExit</key>\n        <false/>\n    </dict>", text, StringComparison.Ordinal);
        Assert.Contains("<key>ThrottleInterval</key>\n    <integer>10</integer>", text, StringComparison.Ordinal);
        Assert.DoesNotContain("<key>KeepAlive</key>\n    <true/>", text, StringComparison.Ordinal);
        Assert.Contains("<key>AXIOM_SERVICE</key>\n        <string>1</string>", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Axiom.app", text, StringComparison.Ordinal);
    }

    [Fact]
    public void NewsyslogEntryRotatesAtFiveMegabytesKeepsFiveCompressed()
    {
        var text = LaunchdServiceInstaller.BuildNewsyslogConf("/Library/Logs/Axiom/axiomd.log");

        var entry = text.Split('\n').Single(line => line.StartsWith("/Library", StringComparison.Ordinal));
        Assert.Equal(["/Library/Logs/Axiom/axiomd.log", "root:wheel", "644", "5", "5120", "*", "J"], entry.Split('\t'));
        Assert.Equal("/etc/newsyslog.d/com.axiom.service.conf", LaunchdServiceInstaller.NewsyslogConfPath);
    }

    [Fact]
    public void RestoreDnsRequiresRootAndIsANoOpWithoutABackup()
    {
        using var temp = new TempDirectory();
        var layout = Layout(temp);
        var runner = new FakeRunner().On("launchctl print", "Could not find service", 113);
        var output = new StringWriter();

        Assert.Equal(5, new LaunchdServiceInstaller(runner, layout, () => false, () => null).RestoreDns(TextWriter.Null, TextWriter.Null));
        Assert.Equal(0, new LaunchdServiceInstaller(runner, layout, () => true, () => null).RestoreDns(output, TextWriter.Null));
        Assert.Contains("nothing to restore", output.ToString(), StringComparison.Ordinal);
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public void RestoreDnsPutsSavedServersBackFromTheBackupWithoutTheDaemon()
    {
        using var temp = new TempDirectory();
        var layout = Layout(temp);
        Directory.CreateDirectory(Path.GetDirectoryName(layout.DnsBackupPath)!);
        File.WriteAllText(layout.DnsBackupPath, """{"schemaVersion":1,"services":[{"name":"Ethernet","servers":["10.0.2.3"]}],"upstreams":["10.0.2.3"]}""");
        var dns = new Dictionary<string, string> { ["Ethernet"] = "127.0.0.1" };
        var runner = new FakeRunner().On("launchctl print", "Could not find service", 113)
            .On("networksetup -listallnetworkservices", "An asterisk (*) denotes that a network service is disabled.\nEthernet\n")
            .On("networksetup -getdnsservers", arguments => new ProcessResult(0, dns[arguments[1]] + "\n", string.Empty))
            .On("networksetup -setdnsservers", arguments =>
            {
                dns[arguments[1]] = string.Join(' ', arguments.Skip(2));
                return new ProcessResult(0, string.Empty, string.Empty);
            });
        var output = new StringWriter();

        var code = new LaunchdServiceInstaller(runner, layout, () => true, () => null).RestoreDns(output, TextWriter.Null);

        Assert.Equal(0, code);
        Assert.Equal("10.0.2.3", dns["Ethernet"]);
        Assert.Contains("Restored system DNS", output.ToString(), StringComparison.Ordinal);
        Assert.False(File.Exists(layout.DnsBackupPath));
    }

    [Fact]
    public void PlistEscapesPaths()
    {
        var text = LaunchdServiceInstaller.BuildPlist("/opt/A&B <x>/axiomd", "/tmp/log");

        Assert.Contains("/opt/A&amp;B &lt;x&gt;/axiomd", text, StringComparison.Ordinal);
        Assert.Equal("/opt/A&B <x>", MacBundleInfo.ParseXmlPlist(text)!["WorkingDirectory"]);
    }

    [Fact]
    public void InstallCopiesToHelperDirectoryVerifiesRecordsOwnerAndBootstraps()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var layout = Layout(temp);
        var bundle = Path.Combine(temp.Path, "Axiom.app", "Contents", "Resources", "service");
        Directory.CreateDirectory(Path.Combine(bundle, "sub"));
        var exe = Path.Combine(bundle, "axiomd");
        File.WriteAllText(exe, "#!/bin/sh\n");
        File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        File.WriteAllText(Path.Combine(bundle, "Axiom.Core.dll"), "dll");
        File.WriteAllText(Path.Combine(bundle, "sub", "data.json"), "{}");
        var runner = StatAsRoot(new FakeRunner().On("launchctl print", "Could not find service", 113));
        var installer = new LaunchdServiceInstaller(runner, layout, () => true, () => 501);

        var output = new StringWriter();
        var code = installer.Install(exe, output, TextWriter.Null);

        Assert.Equal(0, code);
        Assert.True(File.Exists(layout.DaemonPath));
        Assert.Equal("dll", File.ReadAllText(Path.Combine(layout.HelperDirectory, "Axiom.Core.dll")));
        Assert.Equal("{}", File.ReadAllText(Path.Combine(layout.HelperDirectory, "sub", "data.json")));
        Assert.Equal(PrivilegedHelperLayout.ExecutableMode, File.GetUnixFileMode(layout.DaemonPath));
        Assert.Equal(PrivilegedHelperLayout.FileMode, File.GetUnixFileMode(Path.Combine(layout.HelperDirectory, "Axiom.Core.dll")));
        Assert.Equal(PrivilegedHelperLayout.DirectoryMode, File.GetUnixFileMode(Path.Combine(layout.HelperDirectory, "sub")));
        Assert.Single(Directory.GetDirectories(layout.HelperRoot));

        var plist = MacBundleInfo.ParseXmlPlist(File.ReadAllText(layout.PlistPath))!;
        Assert.Equal(layout.HelperDirectory, plist["WorkingDirectory"]);
        Assert.Contains($"<string>{layout.DaemonPath}</string>", File.ReadAllText(layout.PlistPath), StringComparison.Ordinal);

        Assert.Equal(501u, new ProtectionSettingsStore(layout.ProtectionSettingsPath).Load().AllowedUid);
        Assert.Equal(MacDataDirectoryPermissions.PrivateDirectoryMode, File.GetUnixFileMode(layout.MachineDataDirectory));
        Assert.Equal(MacDataDirectoryPermissions.PrivateFileMode, File.GetUnixFileMode(layout.ProtectionSettingsPath));
        Assert.Contains("uid 501", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("axiomd.log\troot:wheel\t644\t5\t5120\t*\tJ", File.ReadAllText(layout.NewsyslogConfPath), StringComparison.Ordinal);
        Assert.Equal(PrivilegedHelperLayout.FileMode, File.GetUnixFileMode(layout.NewsyslogConfPath));

        Assert.Contains(runner.Calls, call => call.StartsWith("chown -R 0:0 ", StringComparison.Ordinal));
        Assert.Equal(
            [
                "launchctl bootout system/com.axiom.service",
                "launchctl enable system/com.axiom.service",
                "launchctl bootstrap system " + layout.PlistPath,
            ],
            runner.Calls.Where(call => call.StartsWith("launchctl", StringComparison.Ordinal)).ToList());

        // Upgrade in place: a second install replaces the copy and leaves no staging directory.
        File.WriteAllText(Path.Combine(bundle, "Axiom.Core.dll"), "dll2");
        Assert.Equal(0, installer.Install(exe, TextWriter.Null, TextWriter.Null));
        Assert.Equal("dll2", File.ReadAllText(Path.Combine(layout.HelperDirectory, "Axiom.Core.dll")));
        Assert.Single(Directory.GetDirectories(layout.HelperRoot));

        File.WriteAllText(layout.DnsBackupPath, "{\"schemaVersion\":1,\"services\":[],\"upstreams\":[]}");
        var uninstallOutput = new StringWriter();
        Assert.Equal(0, installer.Uninstall(uninstallOutput, TextWriter.Null));
        Assert.False(File.Exists(layout.PlistPath));
        Assert.False(Directory.Exists(layout.HelperDirectory));
        Assert.False(File.Exists(layout.NewsyslogConfPath));
        Assert.Contains("networksetup -listallnetworkservices", runner.Calls);
        Assert.Contains("Privacy Shield", uninstallOutput.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void InstallRefusesWhenTheCopyIsNotRootOwned()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var layout = Layout(temp);
        var bundle = Path.Combine(temp.Path, "bundle");
        Directory.CreateDirectory(bundle);
        var exe = Path.Combine(bundle, "axiomd");
        File.WriteAllText(exe, "x");
        var runner = new FakeRunner().On("launchctl print", "Could not find service", 113).On("stat", arguments =>
            new ProcessResult(0, string.Join('\n', arguments.Skip(2).Select(path => $"501 20 {(Directory.Exists(path) ? "40755" : "100755")} {path}")), string.Empty));
        var error = new StringWriter();

        var code = new LaunchdServiceInstaller(runner, layout, () => true, () => 501).Install(exe, TextWriter.Null, error);

        Assert.Equal(3, code);
        Assert.Contains("not root-owned", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("owned by uid 501", error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(runner.Calls, call => call.StartsWith("launchctl bootstrap", StringComparison.Ordinal));
        Assert.False(File.Exists(layout.PlistPath));
        Assert.Empty(Directory.GetDirectories(layout.HelperRoot));
    }

    [Fact]
    public void InstallRequiresRootAndAnExistingExecutable()
    {
        using var temp = new TempDirectory();
        var layout = Layout(temp);
        var runner = new FakeRunner().On("launchctl print", "Could not find service", 113);

        Assert.Equal(5, new LaunchdServiceInstaller(runner, layout, () => false, () => null).Install("/x", TextWriter.Null, TextWriter.Null));
        Assert.Equal(2, new LaunchdServiceInstaller(runner, layout, () => true, () => null).Install(Path.Combine(temp.Path, "missing"), TextWriter.Null, TextWriter.Null));
        Assert.Equal(5, new LaunchdServiceInstaller(runner, layout, () => false, () => null).Uninstall(TextWriter.Null, TextWriter.Null));
        Assert.Empty(runner.Calls);
        Assert.False(File.Exists(layout.PlistPath));
    }

    [Theory]
    [InlineData("501", null, 501u)]
    [InlineData(null, 502u, 502u)]
    [InlineData("0", 501u, 501u)]
    [InlineData("250", 501u, 501u)]
    [InlineData("4294967294", null, null)]
    [InlineData("x", null, null)]
    [InlineData(null, 0u, null)]
    public void InstallOwnerPrefersSudoUidThenConsoleOwner(string? sudoUid, uint? console, uint? expected)
    {
        Assert.Equal(expected, InstallOwner.Resolve(sudoUid, console));
    }

    private static LaunchdInstallerOptions Layout(TempDirectory temp)
    {
        var helperRoot = Path.Combine(temp.Path, "PrivilegedHelperTools");
        Directory.CreateDirectory(Path.Combine(temp.Path, "LaunchDaemons"));
        Directory.CreateDirectory(helperRoot);
        return new LaunchdInstallerOptions(
            Path.Combine(temp.Path, "LaunchDaemons", "com.axiom.service.plist"),
            Path.Combine(temp.Path, "logs"),
            Path.Combine(helperRoot, "com.axiom.service"),
            Path.Combine(temp.Path, "data"),
            Path.Combine(temp.Path, "data", "privacy-shield-dns-backup.json"),
            Path.Combine(temp.Path, "data", "protection.json"),
            Path.Combine(temp.Path, "newsyslog.d", "com.axiom.service.conf"));
    }

    /// <summary>Answers stat with uid 0 and the real on-disk mode (the test cannot chown).</summary>
    internal static FakeRunner StatAsRoot(FakeRunner runner) => runner.On("stat", arguments =>
    {
        var lines = arguments.Skip(2).Where(path => File.Exists(path) || Directory.Exists(path)).Select(path =>
        {
            var directory = Directory.Exists(path);
            var mode = (int)File.GetUnixFileMode(path) | (directory ? 0x4000 : 0x8000);
            return $"0 0 {Convert.ToString(mode, 8)} {path}";
        });
        return new ProcessResult(0, string.Join('\n', lines), string.Empty);
    });
}
