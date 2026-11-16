// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Platform;
using Axiom.Desktop.Avalonia.Linux;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.Desktop.Avalonia.Linux.Tests;

public sealed class TrayDecisionTests
{
    [Theory]
    [InlineData(false, null, false)]
    [InlineData(true, null, true)]
    [InlineData(true, "0", false)]
    [InlineData(false, "1", true)]
    [InlineData(false, "garbage", false)]
    public void Tray_only_with_a_watcher_unless_overridden(bool watcher, string? overrideValue, bool expected) =>
        Assert.Equal(expected, StatusNotifierProbe.ShouldCreateTray(watcher, overrideValue));

    [Fact]
    public void NameHasOwner_reply_is_parsed()
    {
        Assert.True(StatusNotifierProbe.ParseNameHasOwner("method return time=1.0 sender=org.freedesktop.DBus\n   boolean true\n"));
        Assert.False(StatusNotifierProbe.ParseNameHasOwner("method return ...\n   boolean false\n"));
        Assert.False(StatusNotifierProbe.ParseNameHasOwner(string.Empty));
    }

    [Theory]
    [InlineData(false, true, true, true)]
    [InlineData(false, false, true, false)]
    [InlineData(false, true, false, false)]
    [InlineData(true, true, true, false)]
    public void Close_hides_only_with_a_tray(bool exiting, bool tray, bool enabled, bool expected) =>
        Assert.Equal(expected, App.ShouldHideToTray(exiting, tray, enabled));

    [Fact]
    public void Menu_header_reads_as_state_once_running()
    {
        Assert.Equal("Install Background Service…", App.MenuHeaders.Install(false));
        Assert.Equal("Service: running", App.MenuHeaders.Install(true));
    }
}

public sealed class LinuxAutostartServiceTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "axiom-autostart-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void Enable_writes_desktop_entry_with_autostart_argument()
    {
        var service = new LinuxAutostartService("/opt/axiom/Axiom", _directory);
        Assert.True(service.IsSupported);
        Assert.False(service.IsEnabled);
        Assert.Equal("Autostart: off", service.StatusText);

        Assert.True(service.SetEnabled(true));

        var text = File.ReadAllText(service.EntryPath);
        Assert.Equal(Path.Combine(_directory, "com.axiom.firewall.desktop"), service.EntryPath);
        Assert.StartsWith("[Desktop Entry]", text, StringComparison.Ordinal);
        Assert.Contains("Exec=\"/opt/axiom/Axiom\" --autostart", text, StringComparison.Ordinal);
        Assert.Contains("X-GNOME-Autostart-enabled=true", text, StringComparison.Ordinal);
        Assert.Contains("Type=Application", text, StringComparison.Ordinal);
        Assert.True(service.IsEnabled);
        Assert.False(service.CanRepair);
        Assert.Equal("Autostart: active (~/.config/autostart)", service.StatusText);

        Assert.True(service.SetEnabled(false));
        Assert.False(File.Exists(service.EntryPath));
    }

    [Fact]
    public void Moved_executable_is_reported_stale_and_repaired()
    {
        Assert.True(new LinuxAutostartService("/old/Axiom", _directory).SetEnabled(true));
        var moved = new LinuxAutostartService("/new/Axiom", _directory);
        Assert.True(moved.IsEnabled);
        Assert.True(moved.CanRepair);
        Assert.True(moved.Repair());
        Assert.False(moved.CanRepair);
    }

    [Fact]
    public void Exec_quoting_escapes_desktop_entry_specials() =>
        Assert.Equal("\"/opt/my \\\"app\\\"/\\$bin\" --autostart", LinuxAutostartService.BuildExec("/opt/my \"app\"/$bin"));

    [Fact]
    public void Missing_executable_path_is_unsupported()
    {
        var service = new LinuxAutostartService(string.Empty, _directory);
        Assert.False(service.IsSupported);
        Assert.False(service.SetEnabled(true));
        Assert.Equal("Autostart: unavailable", service.StatusText);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}

public sealed class SecretProtectorTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "axiom-secret-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void Protect_then_unprotect_round_trips_without_plaintext()
    {
        var store = new MemoryKeyStore();
        var protector = new SecretServiceApiKeyProtector(store);

        var sealedText = protector.Protect("test-key-123");

        Assert.StartsWith(SecretServiceApiKeyProtector.Prefix, sealedText, StringComparison.Ordinal);
        Assert.DoesNotContain("test-key-123", sealedText, StringComparison.Ordinal);
        Assert.Equal("test-key-123", protector.Unprotect(sealedText));
        Assert.Equal(1, store.Saves);
        Assert.Null(protector.Unprotect("kc1:AAAA"));
        Assert.Null(protector.Unprotect("AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA"));
    }

    [Fact]
    public void File_store_writes_0600_in_0700_directory_and_never_overwrites()
    {
        var path = Path.Combine(_directory, "secret-protection-key");
        var store = new FileSecretKeyStore(path);
        Assert.Null(store.Load());

        var key = new byte[32];
        key[0] = 7;
        Assert.True(store.Save(key));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(_directory));
        Assert.Equal(key, store.Load());

        Assert.False(store.Save(new byte[32]));
        Assert.Equal(key, store.Load());
    }

    [Fact]
    public void Without_secret_tool_the_file_store_is_used_alone()
    {
        var file = new MemoryKeyStore();
        Assert.Same(file, SecretKeyStores.Choose(null, file));
        Assert.IsType<ChainedSecretKeyStore>(SecretKeyStores.Choose("/usr/bin/secret-tool", file));
    }

    [Fact]
    public void Chain_falls_back_to_the_file_store_when_the_keyring_refuses()
    {
        var refusing = new MemoryKeyStore { Refuse = true };
        var file = new MemoryKeyStore();
        var chain = new ChainedSecretKeyStore(refusing, file);
        var protector = new SecretServiceApiKeyProtector(chain);
        var sealedText = protector.Protect("test-key-123");
        Assert.Equal(0, refusing.Saves);
        Assert.Equal(1, file.Saves);
        Assert.Equal("test-key-123", new SecretServiceApiKeyProtector(chain).Unprotect(sealedText));
    }

    [Fact]
    public void Secret_tool_arguments_never_carry_the_secret()
    {
        Assert.Equal(["lookup", "service", "com.axiom.firewall", "account", "secret-protection-key"], SecretToolKeyStore.LookupArguments);
        Assert.Contains("store", SecretToolKeyStore.StoreArguments);
        Assert.DoesNotContain(SecretToolKeyStore.StoreArguments, argument => argument.Contains("--secret", StringComparison.Ordinal));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private sealed class MemoryKeyStore : ISecretKeyStore
    {
        private byte[]? _key;

        public int Saves { get; private set; }

        public bool Refuse { get; init; }

        public byte[]? Load() => _key;

        public bool Save(byte[] key)
        {
            if (Refuse || _key is not null)
            {
                return false;
            }

            _key = key;
            Saves++;
            return true;
        }
    }
}

public sealed class LinuxThemeServiceTests
{
    [Theory]
    [InlineData(0, "method return time=1 sender=:1.1\n   variant       variant          uint32 1\n", UiTheme.Dark)]
    [InlineData(0, "   variant       variant          uint32 2\n", UiTheme.Light)]
    [InlineData(0, "   variant       variant          uint32 0\n", UiTheme.Dark)]
    [InlineData(1, "Error org.freedesktop.DBus.Error.ServiceUnknown", UiTheme.Dark)]
    [InlineData(0, "", UiTheme.Dark)]
    public void Portal_color_scheme_maps_to_theme(int exitCode, string output, UiTheme expected) =>
        Assert.Equal(expected, LinuxThemeService.FromPortalColorScheme(exitCode, output));

    [Fact]
    public void Platform_variant_maps_to_theme()
    {
        Assert.Equal(UiTheme.Light, LinuxThemeService.FromPlatform(PlatformThemeVariant.Light));
        Assert.Equal(UiTheme.Dark, LinuxThemeService.FromPlatform(PlatformThemeVariant.Dark));
    }
}

public sealed class ProcessActionsTests
{
    [Theory]
    [InlineData(0, 500, 1000u, 1000u, ProcessActionRefusal.InvalidPid)]
    [InlineData(1, 500, 1000u, 0u, ProcessActionRefusal.InitProcess)]
    [InlineData(500, 500, 1000u, 1000u, ProcessActionRefusal.OwnProcess)]
    [InlineData(42, 500, 1000u, 0u, ProcessActionRefusal.RootOwned)]
    [InlineData(42, 500, 1000u, 1001u, ProcessActionRefusal.ForeignUser)]
    [InlineData(42, 500, 1000u, 1000u, ProcessActionRefusal.None)]
    [InlineData(42, 500, 0u, 0u, ProcessActionRefusal.None)]
    public void Refusals(int pid, int ownPid, uint ownUid, uint targetUid, ProcessActionRefusal expected) =>
        Assert.Equal(expected, ProcessActions.Decide(pid, ownPid, ownUid, targetUid));

    [Fact]
    public void Missing_process_is_refused() =>
        Assert.Equal(ProcessActionRefusal.NotFound, ProcessActions.Decide(42, 500, 1000, null));

    [Fact]
    public void Status_uid_line_yields_the_real_uid()
    {
        Assert.Equal(1000u, ProcessActions.ParseUidLine("Uid:\t1000\t1000\t1000\t1000"));
        Assert.Null(ProcessActions.ParseUidLine("Uid:"));
    }

    [Fact]
    public void Term_then_kill_after_grace_only_for_survivors()
    {
        var signals = new List<(int Pid, int Signal)>();
        var alive = new HashSet<int> { 10, 11 };
        var actions = new ProcessActions(
            pid => pid == 12 ? 0u : 1000u,
            ownPid: 1,
            ownUid: 1000,
            (pid, signal) =>
            {
                signals.Add((pid, signal));
                if (pid == 10)
                {
                    alive.Remove(10);
                }

                return true;
            },
            alive.Contains,
            TimeSpan.FromMilliseconds(150));

        var ended = actions.EndProcesses([10, 11, 12, 1]);

        Assert.Equal(2, ended);
        Assert.Equal([(10, 15), (11, 15), (11, 9)], signals);
    }
}

public sealed class ProtectionSetupTests
{
    [Fact]
    public void Daemon_state_classification()
    {
        Assert.Equal(DaemonState.Running, LinuxProtectionSetup.Classify(connected: true, installed: false));
        Assert.Equal(DaemonState.InstalledNotResponding, LinuxProtectionSetup.Classify(connected: false, installed: true));
        Assert.Equal(DaemonState.NotInstalled, LinuxProtectionSetup.Classify(connected: false, installed: false));
    }

    [Fact]
    public void Startup_offer_only_for_a_hand_run_bundle_without_daemon()
    {
        Assert.True(LinuxProtectionSetup.ShouldOfferInstallAtStartup(DaemonState.NotInstalled, declined: false, packageManaged: false));
        Assert.False(LinuxProtectionSetup.ShouldOfferInstallAtStartup(DaemonState.NotInstalled, declined: true, packageManaged: false));
        Assert.False(LinuxProtectionSetup.ShouldOfferInstallAtStartup(DaemonState.NotInstalled, declined: false, packageManaged: true));
        Assert.False(LinuxProtectionSetup.ShouldOfferInstallAtStartup(DaemonState.Running, declined: false, packageManaged: false));
        Assert.False(LinuxProtectionSetup.ShouldOfferInstallAtStartup(DaemonState.InstalledNotResponding, declined: false, packageManaged: false));
    }

    [Fact]
    public void Package_prefix_marks_the_layout_as_package_managed()
    {
        Assert.True(new LinuxDaemonLayout("/usr/lib/axiom-firewall").IsPackageManaged);
        Assert.True(new LinuxDaemonLayout("/usr/lib/axiom-firewall/").IsPackageManaged);
        Assert.False(new LinuxDaemonLayout("/usr/lib/axiom-firewall-dev").IsPackageManaged);
        Assert.False(new LinuxDaemonLayout("/opt/axiom").IsPackageManaged);
        Assert.False(new LinuxDaemonLayout("/home/user/Axiom").IsPackageManaged);
        Assert.False(LinuxDaemonLayout.IsUnderPackagePrefix("/home/user/build/linux/Axiom"));
    }

    [Fact]
    public void Pkexec_command_line_is_the_daemon_and_install_flag()
    {
        var arguments = LinuxElevation.BuildArguments("/usr/libexec/axiom/axiomd", "--install-service");
        Assert.Equal(["/usr/libexec/axiom/axiomd", "--install-service"], arguments);
        Assert.Equal("/usr/bin/pkexec", LinuxElevation.PkexecPath);
        Assert.Equal("/usr/share/polkit-1/actions/com.axiom.firewall.policy", LinuxElevation.PolicyFilePath);
    }

    [Fact]
    public void Layout_prefers_the_bundled_daemon_and_falls_back_to_the_installed_image()
    {
        var root = Path.Combine(Path.GetTempPath(), "axiom-layout-" + Guid.NewGuid().ToString("N"));
        try
        {
            var layout = new LinuxDaemonLayout(root);
            Assert.Equal(Path.Combine(root, "axiomd", "axiomd"), layout.BundledDaemonPath);
            Assert.Equal("/usr/libexec/axiom/axiomd", layout.DaemonPath);
            Directory.CreateDirectory(Path.Combine(root, "axiomd"));
            File.WriteAllText(layout.BundledDaemonPath, string.Empty);
            Assert.Equal(layout.BundledDaemonPath, layout.DaemonPath);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData(0, false, true)]
    [InlineData(126, true, false)]
    [InlineData(127, true, false)]
    [InlineData(1, false, false)]
    public void Pkexec_exit_codes(int exitCode, bool cancelled, bool succeeded)
    {
        var result = new LinuxElevationResult(exitCode, string.Empty, string.Empty);
        Assert.Equal(cancelled, result.Cancelled);
        Assert.Equal(succeeded, result.Succeeded);
    }

    [Fact]
    public async Task Install_reports_cancel_and_failure_detail()
    {
        var root = Path.Combine(Path.GetTempPath(), "axiom-install-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "axiomd"));
        File.WriteAllText(Path.Combine(root, "axiomd", "axiomd"), string.Empty);
        try
        {
            var layout = new LinuxDaemonLayout(root);
            IReadOnlyList<string>? seen = null;
            var cancelled = await ProtectionServiceInstall.InstallAndStartLinuxAsync(
                layout,
                (arguments, _) =>
                {
                    seen = arguments;
                    return Task.FromResult(new LinuxElevationResult(126, string.Empty, string.Empty));
                },
                CancellationToken.None);
            Assert.False(cancelled.Success);
            Assert.Equal("Administrator approval was cancelled.", cancelled.Message);
            Assert.Equal([layout.BundledDaemonPath, "--install-service"], seen);

            var failed = await ProtectionServiceInstall.InstallAndStartLinuxAsync(
                layout,
                (_, _) => Task.FromResult(new LinuxElevationResult(3, string.Empty, "Refusing to start: not root-owned\n")),
                CancellationToken.None);
            Assert.Equal("The daemon installer exited with code 3: Refusing to start: not root-owned", failed.Message);

            var ok = await ProtectionServiceInstall.InstallAndStartLinuxAsync(
                layout,
                (_, _) => Task.FromResult(new LinuxElevationResult(0, "Installed", string.Empty)),
                CancellationToken.None);
            Assert.True(ok.Success);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}

public sealed class LinuxPathsAndWordingTests
{
    [Fact]
    public void State_runtime_and_autostart_follow_xdg()
    {
        Assert.Equal("/x/state/axiom", LinuxPaths.StateDirectoryFor("/x/state", "/home/u"));
        Assert.Equal("/home/u/.local/state/axiom", LinuxPaths.StateDirectoryFor(null, "/home/u"));
        Assert.Equal("/home/u/.config/autostart", LinuxPaths.AutostartDirectoryFor(null, "/home/u"));
        Assert.Equal("/cfg/autostart", LinuxPaths.AutostartDirectoryFor("/cfg", "/home/u"));
        Assert.Equal("/fallback", LinuxPaths.RuntimeDirectoryFor("/nonexistent-runtime-dir", "/fallback"));
        Assert.Equal(Path.GetTempPath().TrimEnd('/'), LinuxPaths.RuntimeDirectoryFor(Path.GetTempPath().TrimEnd('/'), "/fallback"));
    }

    [Fact]
    public void Linux_wording_names_the_platform_pieces()
    {
        Assert.Equal("Linux", PlatformText.OsName);
        Assert.Equal("nftables firewall", PlatformText.Firewall);
        Assert.Equal("background service (systemd daemon)", PlatformText.ServiceKind);
        Assert.Contains("systemctl status axiomd", PlatformText.ServiceCheckHint, StringComparison.Ordinal);
        Assert.Equal("the polkit authentication prompt", PlatformText.ElevationPrompt);
        Assert.Equal("Unix socket", PlatformText.IpcTransport);
        Assert.Equal("keyring", PlatformText.SecretStoreShort);
        Assert.Equal("Start at login", PlatformText.StartWithOs);
        Assert.Contains("~/.config/autostart", PlatformText.StartupScopeNote, StringComparison.Ordinal);
        Assert.Equal("systemd-resolved", PlatformText.DnsResolverName);
        Assert.True(PlatformText.DaemonSwitchesDns);
        Assert.Contains("systemd-resolved", PlatformText.AdapterDnsTitle, StringComparison.Ordinal);
    }

    [Fact]
    public void Relaunch_command_detaches_the_new_copy()
    {
        Assert.Equal("sleep 2; '/opt/axiom/Axiom' '--autostart' >/dev/null 2>&1 &", AvaloniaShellActions.BuildRelaunchCommand("/opt/axiom/Axiom", ["--autostart"]));
        Assert.Null(AvaloniaShellActions.BuildRelaunchCommand(null, []));
    }
}

public sealed class ResolvedLinkDnsTests
{
    [Fact]
    public void Resolvectl_dns_output_maps_links_to_servers()
    {
        var links = ResolvedLinkDns.Parse("Global:\nLink 2 (eno2): 192.168.70.1 fe80::1%eno2\nLink 3 (wlo1):\nLink 7 (tailscale0): 100.100.100.100#dns.tailscale\n");
        Assert.Equal(["192.168.70.1", "fe80::1"], links["eno2"].Select(address => address.ToString()));
        Assert.Empty(links["wlo1"]);
        Assert.Equal(["100.100.100.100"], links["tailscale0"].Select(address => address.ToString()));
        Assert.False(links.ContainsKey("Global"));
    }

    [Fact]
    public void Stub_listeners_are_not_the_privacy_shield_resolver()
    {
        Assert.True(ResolvedLinkDns.IsStub(System.Net.IPAddress.Parse("127.0.0.53")));
        Assert.True(ResolvedLinkDns.IsStub(System.Net.IPAddress.Parse("127.0.0.54")));
        Assert.False(ResolvedLinkDns.IsStub(System.Net.IPAddress.Loopback));
    }
}
