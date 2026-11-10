// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.MacOS.Launchd;
using Axiom.Infrastructure.MacOS.ProcessIdentity;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class LaunchdServiceInstallerTests
{
    [Fact]
    public void PlistDefinesTheDaemonJob()
    {
        var text = LaunchdServiceInstaller.BuildPlist("/Applications/Axiom.app/Contents/Resources/service/axiomd", "/Library/Logs/Axiom/axiomd.log");

        Assert.StartsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", text, StringComparison.Ordinal);
        var values = MacBundleInfo.ParseXmlPlist(text);
        Assert.NotNull(values);
        Assert.Equal("com.axiom.service", values["Label"]);
        Assert.Equal("/Applications/Axiom.app/Contents/Resources/service", values["WorkingDirectory"]);
        Assert.Equal("Interactive", values["ProcessType"]);
        Assert.Equal("/Library/Logs/Axiom/axiomd.log", values["StandardOutPath"]);
        Assert.Equal("/Library/Logs/Axiom/axiomd.log", values["StandardErrorPath"]);
        Assert.Contains("<string>/Applications/Axiom.app/Contents/Resources/service/axiomd</string>", text, StringComparison.Ordinal);
        Assert.Contains("<key>RunAtLoad</key>\n    <true/>", text, StringComparison.Ordinal);
        Assert.Contains("<key>KeepAlive</key>\n    <true/>", text, StringComparison.Ordinal);
        Assert.Contains("<key>AXIOM_SERVICE</key>\n        <string>1</string>", text, StringComparison.Ordinal);
    }

    [Fact]
    public void PlistEscapesPaths()
    {
        var text = LaunchdServiceInstaller.BuildPlist("/opt/A&B <x>/axiomd", "/tmp/log");

        Assert.Contains("/opt/A&amp;B &lt;x&gt;/axiomd", text, StringComparison.Ordinal);
        Assert.Equal("/opt/A&B <x>", MacBundleInfo.ParseXmlPlist(text)!["WorkingDirectory"]);
    }

    [Fact]
    public void InstallWritesPlistAndBootstraps()
    {
        using var temp = new TempDirectory();
        var exe = Path.Combine(temp.Path, "axiomd");
        File.WriteAllText(exe, "x");
        var plist = Path.Combine(temp.Path, "LaunchDaemons", "com.axiom.service.plist");
        Directory.CreateDirectory(Path.GetDirectoryName(plist)!);
        var runner = new FakeRunner();
        var installer = new LaunchdServiceInstaller(runner, plist, Path.Combine(temp.Path, "logs"), () => true);

        var code = installer.Install(exe, TextWriter.Null, TextWriter.Null);

        Assert.Equal(0, code);
        Assert.True(File.Exists(plist));
        Assert.Equal(exe, MacBundleInfo.ParseXmlPlist(File.ReadAllText(plist))!["WorkingDirectory"] + "/axiomd");
        Assert.Equal(
            [
                "launchctl bootout system/com.axiom.service",
                "launchctl enable system/com.axiom.service",
                "launchctl bootstrap system " + plist,
            ],
            runner.Calls);

        Assert.Equal(0, installer.Uninstall(TextWriter.Null, TextWriter.Null));
        Assert.False(File.Exists(plist));
        Assert.Equal("launchctl bootout system/com.axiom.service", runner.Calls[^1]);
    }

    [Fact]
    public void InstallRequiresRootAndAnExistingExecutable()
    {
        using var temp = new TempDirectory();
        var plist = Path.Combine(temp.Path, "p.plist");
        var runner = new FakeRunner();

        Assert.Equal(5, new LaunchdServiceInstaller(runner, plist, temp.Path, () => false).Install("/x", TextWriter.Null, TextWriter.Null));
        Assert.Equal(2, new LaunchdServiceInstaller(runner, plist, temp.Path, () => true).Install(Path.Combine(temp.Path, "missing"), TextWriter.Null, TextWriter.Null));
        Assert.Equal(5, new LaunchdServiceInstaller(runner, plist, temp.Path, () => false).Uninstall(TextWriter.Null, TextWriter.Null));
        Assert.Empty(runner.Calls);
        Assert.False(File.Exists(plist));
    }
}
