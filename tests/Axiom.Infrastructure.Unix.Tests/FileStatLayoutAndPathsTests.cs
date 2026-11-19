// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Axiom.Infrastructure.Unix.Filter;
using Axiom.Infrastructure.Unix.Install;
using Axiom.Infrastructure.Unix.Interop;
using Axiom.Infrastructure.Unix.Monitoring;

namespace Axiom.Infrastructure.Unix.Tests;

public sealed class FileStatLayoutAndPathsTests
{
    [Fact]
    public void GnuStatUsesDashCAndHexModes()
    {
        var runner = new FakeRunner().On("stat -c", "0 0 41ed /usr/libexec/axiom\n0 0 81ed /usr/libexec/axiom/axiomd\n1000 1000 81a4 /tmp/x\nbroken line\n");

        var entries = UnixFileStat.List(runner, ["/usr/libexec/axiom", "/usr/libexec/axiom/axiomd", "/tmp/x"], StatFlavor.Gnu);

        Assert.Equal("stat -c %u %g %f %n /usr/libexec/axiom /usr/libexec/axiom/axiomd /tmp/x", runner.Calls.Single());
        Assert.Equal(3, entries.Count);
        Assert.True(entries[0].IsDirectory);
        Assert.Equal("755", entries[0].PermissionsOctal);
        Assert.True(entries[1].IsRootOwned);
        Assert.Equal(0x1ED, entries[1].Permissions);
        Assert.Equal(1000u, entries[2].Uid);
        Assert.Equal("644", entries[2].PermissionsOctal);
    }

    [Fact]
    public void BsdStatIsTheDefaultAndStillOctal()
    {
        var runner = new FakeRunner().On("stat -f", "0 0 40755 /Library/PrivilegedHelperTools/com.axiom.service\n");

        var entry = UnixFileStat.Stat(runner, "/Library/PrivilegedHelperTools/com.axiom.service");

        Assert.NotNull(entry);
        Assert.True(entry.IsDirectory);
        Assert.StartsWith("stat -f %u %g %p %N ", runner.Calls.Single(), StringComparison.Ordinal);
    }

    [Fact]
    public void ProtectedImageAuditFlagsNonRootAndWritableEntries()
    {
        var image = "/usr/libexec/axiom";
        var entries = new List<UnixFileEntry>
        {
            new(image, 0, 0, 0x41ED),
            new(image + "/axiomd", 1000, 0, 0x81ED),
            new(image + "/Axiom.Core.dll", 0, 0, 0x81B6),
        };

        var problems = ProtectedImageLayout.Audit(image, entries);

        Assert.Equal(2, problems.Count);
        Assert.Contains(problems, problem => problem.Contains("owned by uid 1000", StringComparison.Ordinal));
        Assert.Contains(problems, problem => problem.Contains("group- or world-writable", StringComparison.Ordinal));
        Assert.Empty(ProtectedImageLayout.Audit(image, [entries[0], entries[1] with { Uid = 0 }]));
        Assert.Contains("missing", ProtectedImageLayout.Audit(image, [entries[0]]).Single(), StringComparison.Ordinal);
    }

    [Fact]
    public void FilesMatchComparesContentHashes()
    {
        using var temp = new TempDirectory();
        var a = Path.Combine(temp.Path, "a");
        var b = Path.Combine(temp.Path, "b");
        File.WriteAllText(a, "same");
        File.WriteAllText(b, "same");
        Assert.True(ProtectedImageLayout.FilesMatch(a, b));
        File.WriteAllText(b, "other");
        Assert.False(ProtectedImageLayout.FilesMatch(a, b));
        Assert.False(ProtectedImageLayout.FilesMatch(a, Path.Combine(temp.Path, "missing")));
    }

    [Fact]
    public void ServicePathsDeriveFromDataAndRunDirectories()
    {
        var paths = UnixServicePaths.ForRoot("/tmp/root");

        Assert.Equal("/tmp/root/data/filter/rules.json", paths.RulesFile);
        Assert.Equal("/tmp/root/data/filter/managed-rules.json", paths.ManagedRulesFile);
        Assert.Equal("/tmp/root/run/filter.sock", paths.FilterSocketPath);
        Assert.Equal("/tmp/root/run/axiom.sock", paths.IpcSocketPath);
        Assert.Equal("/tmp/root/data/privacy-shield-dns-backup.json", paths.DnsBackupFile);
        Assert.EndsWith("/network-recovery.txt", paths.RecoverySnapshotFile, StringComparison.Ordinal);
        Assert.Equal("/x/filter.sock", (paths with { FilterSocketOverride = " /x/filter.sock " }).FilterSocketPath);
    }

    [Fact]
    public void ManagedRuleStoreRoundTripsAndMarksOwnership()
    {
        using var temp = new TempDirectory();
        var store = new ManagedRuleStore(Path.Combine(temp.Path, "filter", "managed-rules.json"));
        Assert.Empty(store.Load().Rules);

        var id = Guid.NewGuid();
        var rule = new ManagedRule
        {
            ManagedRuleId = id,
            OsRuleName = OwnedRuleName.Create(id, FirewallDirection.Outbound),
            OwnershipGroup = string.Empty,
            Spec = new RuleSpec { ManagedRuleId = id, AppPath = "/usr/bin/curl", Direction = FirewallDirection.Outbound, Action = FirewallAction.Block, CreatedBy = "uid:1000" },
            State = RuleState.Desired,
        };
        store.Save(new ManagedRuleState { Generation = 3, Rules = [rule] });

        var loaded = store.Load();
        Assert.Equal(3, loaded.Generation);
        Assert.Equal(OwnedRuleOwnership.GroupName, loaded.Rules.Single().OwnershipGroup);
        Assert.Equal("/usr/bin/curl", loaded.Rules.Single().Spec.AppPath);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(FilterRulesFile.PrivateMode, File.GetUnixFileMode(store.Path));
        }

        File.WriteAllText(store.Path, "{not json");
        Assert.Empty(store.Load().Rules);
    }

    [Fact]
    public void EndpointTextFormatsFamiliesAndMappedAddresses()
    {
        Assert.Equal("1.2.3.4:443", EndpointText.Format("1.2.3.4", 443));
        Assert.Equal("[::1]:53", EndpointText.Format("::1", 53));
        Assert.Equal("10.0.0.1:80", EndpointText.Format(System.Net.IPAddress.Parse("::ffff:10.0.0.1"), 80));
        Assert.Equal("—", EndpointText.Format(string.Empty, 0));
        Assert.Equal("host:1", EndpointText.Format("host", 1));
        Assert.True(EndpointText.IsAny(System.Net.IPAddress.IPv6Any));
    }

    [Fact]
    public void PeerCredentialsReadTheConnectingUidOverSoPeerCred()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var temp = new TempDirectory();
        var path = Path.Combine(temp.Path, "peer.sock");
        using var listener = UnixSocketListener.Create(path, UnixSocketListener.PrivateSocketMode);
        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        client.Connect(new UnixDomainSocketEndPoint(path));
        using var accepted = listener.Accept();

        Assert.True(UnixPeerCredentials.TryGetPeerUid(accepted, out var uid));
        Assert.Equal(GetEuid(), uid);
        Assert.Equal(UnixSocketListener.PrivateSocketMode, File.GetUnixFileMode(path));
    }

    private static uint GetEuid() => NativeMethods.geteuid();

    private static class NativeMethods
    {
        [System.Runtime.InteropServices.DllImport("libc")]
        internal static extern uint geteuid();
    }
}
