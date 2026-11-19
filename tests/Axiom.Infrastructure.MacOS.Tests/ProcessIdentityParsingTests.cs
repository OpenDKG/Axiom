// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.MacOS.ProcessIdentity;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class ProcessIdentityParsingTests
{
    // Shapes of `codesign -dv --verbose=2 <path>` stderr captured on macOS 15.
    private const string DeveloperId = """
        Executable=/Applications/Firefox.app/Contents/MacOS/firefox
        Identifier=org.mozilla.firefox
        Format=app bundle with Mach-O universal (x86_64 arm64)
        CodeDirectory v=20500 size=749 flags=0x10000(runtime) hashes=12+7 location=embedded
        Signature size=9035
        Authority=Developer ID Application: Mozilla Corporation (43AQ936H96)
        Authority=Developer ID Certification Authority
        Authority=Apple Root CA
        Timestamp=1 Nov 2026 at 10:00:00
        Info.plist entries=29
        TeamIdentifier=43AQ936H96
        Runtime Version=14.0.0
        Sealed Resources version=2 rules=13 files=105
        Internal requirements count=1 size=184
        """;

    private const string Platform = """
        Executable=/usr/bin/curl
        Identifier=com.apple.curl
        Format=Mach-O universal (x86_64 arm64e)
        CodeDirectory v=20400 size=1201 flags=0x0(none) hashes=32+7 location=embedded
        Platform identifier=16
        Signature size=4442
        Authority=Software Signing
        Authority=Apple Code Signing Certification Authority
        Authority=Apple Root CA
        Signed Time=1 Nov 2026 at 10:00:00
        Info.plist=not bound
        TeamIdentifier=not set
        Sealed Resources=none
        Internal requirements count=1 size=64
        """;

    private const string AdHoc = """
        Executable=/Users/dev/x/axiomd
        Identifier=axiomd
        Format=Mach-O thin (x86_64)
        CodeDirectory v=20400 size=5000 flags=0x20002(adhoc,linker-signed) hashes=150+0 location=embedded
        Signature=adhoc
        Info.plist=not bound
        TeamIdentifier=not set
        Sealed Resources=none
        Internal requirements=none
        """;

    [Fact]
    public void ParsesDeveloperIdSignature()
    {
        var info = CodeSignatureInfo.Parse(DeveloperId, verified: true);

        Assert.Equal("Developer ID Application: Mozilla Corporation (43AQ936H96)", info.SignerName);
        Assert.Equal("43AQ936H96", info.TeamId);
        Assert.Equal("org.mozilla.firefox", info.Identifier);
        Assert.Equal("Valid", info.Status);
    }

    [Fact]
    public void ParsesPlatformBinary()
    {
        var info = CodeSignatureInfo.Parse(Platform, verified: true);

        Assert.Equal("Software Signing", info.SignerName);
        Assert.Equal(string.Empty, info.TeamId);
        Assert.Equal("com.apple.curl", info.Identifier);
        Assert.Equal("Valid", info.Status);
    }

    [Fact]
    public void ParsesAdHocUnsignedAndInvalid()
    {
        var adhoc = CodeSignatureInfo.Parse(AdHoc, verified: true);
        Assert.Equal("Ad hoc", adhoc.SignerName);
        Assert.Equal("AdHoc", adhoc.Status);

        var unsigned = CodeSignatureInfo.Parse("/tmp/x: code object is not signed at all\n", verified: false);
        Assert.Equal("Unsigned", unsigned.Status);
        Assert.Equal(string.Empty, unsigned.SignerName);

        Assert.Equal("Invalid", CodeSignatureInfo.Parse(DeveloperId, verified: false).Status);
        Assert.Equal("Signed", CodeSignatureInfo.Parse(DeveloperId, verified: null).Status);
    }

    [Fact]
    public void ParsesInfoPlistStringKeys()
    {
        const string plist = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>CFBundleExecutable</key>
                <string>firefox</string>
                <key>CFBundleIdentifier</key>
                <string>org.mozilla.firefox</string>
                <key>CFBundleName</key>
                <string>Firefox</string>
                <key>LSUIElement</key>
                <true/>
                <key>CFBundleDocumentTypes</key>
                <array><dict><key>CFBundleTypeName</key><string>HTML</string></dict></array>
                <key>CFBundleShortVersionString</key>
                <string>140.0</string>
                <key>CFBundleVersion</key>
                <string>14025.11.1</string>
            </dict>
            </plist>
            """;

        var values = MacBundleInfo.ParseXmlPlist(plist);

        Assert.NotNull(values);
        Assert.Equal("org.mozilla.firefox", values["CFBundleIdentifier"]);
        Assert.False(values.ContainsKey("CFBundleTypeName"));
        Assert.False(values.ContainsKey("LSUIElement"));

        var bundle = MacBundleInfo.FromPlist("/Applications/Firefox.app", values);
        Assert.Equal(new MacBundleInfo("/Applications/Firefox.app", "org.mozilla.firefox", "Firefox", "140.0"), bundle);
    }

    [Fact]
    public void BundleNameFallsBackToFolderName()
    {
        var bundle = MacBundleInfo.FromPlist("/Applications/Tool.app", new Dictionary<string, string> { ["CFBundleVersion"] = "7" });

        Assert.Equal("Tool", bundle.Name);
        Assert.Equal("7", bundle.Version);
        Assert.Null(MacBundleInfo.ParseXmlPlist("bplist00\u0001\u0002"));
        Assert.Null(MacBundleInfo.ParseXmlPlist("<plist><dict><key>broken"));
    }

    [Theory]
    [InlineData("/Applications/Foo.app/Contents/MacOS/Foo", "/Applications/Foo.app")]
    [InlineData("/Applications/Foo.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper", "/Applications/Foo.app")]
    [InlineData("/usr/bin/curl", null)]
    [InlineData("relative/Foo.app/x", null)]
    [InlineData("", null)]
    public void FindsOutermostBundle(string path, string? expected)
    {
        Assert.Equal(expected, MacBundleInfo.FindEnclosingBundle(path));
    }
}
