// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Platform;
using Axiom.Desktop.Avalonia.MacOS;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Desktop.Avalonia.MacOS.Tests;

public sealed class KeychainApiKeyProtectorTests
{
    [Fact]
    public void Protect_then_unprotect_round_trips_without_plaintext()
    {
        var store = new MemoryKeyStore();
        var protector = new KeychainApiKeyProtector(store);

        var sealedText = protector.Protect("sk-test-secret-123");

        Assert.StartsWith(KeychainApiKeyProtector.Prefix, sealedText, StringComparison.Ordinal);
        Assert.DoesNotContain("sk-test-secret-123", sealedText, StringComparison.Ordinal);
        Assert.Equal("sk-test-secret-123", protector.Unprotect(sealedText));
        Assert.Equal(1, store.Saves);
    }

    [Fact]
    public void Key_is_reused_across_instances_and_secrets()
    {
        var store = new MemoryKeyStore();
        var first = new KeychainApiKeyProtector(store).Protect("one");
        var second = new KeychainApiKeyProtector(store).Protect("two");

        var reader = new KeychainApiKeyProtector(store);
        Assert.Equal("one", reader.Unprotect(first));
        Assert.Equal("two", reader.Unprotect(second));
        Assert.Equal(1, store.Saves);
    }

    [Fact]
    public void Same_plaintext_seals_differently_each_time()
    {
        var protector = new KeychainApiKeyProtector(new MemoryKeyStore());
        Assert.NotEqual(protector.Protect("same"), protector.Protect("same"));
    }

    [Fact]
    public void Tampered_or_foreign_values_return_null()
    {
        var protector = new KeychainApiKeyProtector(new MemoryKeyStore());
        var sealedText = protector.Protect("secret");
        var bytes = Convert.FromBase64String(sealedText[KeychainApiKeyProtector.Prefix.Length..]);
        bytes[^1] ^= 0x01;

        Assert.Null(protector.Unprotect(KeychainApiKeyProtector.Prefix + Convert.ToBase64String(bytes)));
        Assert.Null(protector.Unprotect("AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA")); // a DPAPI blob from Windows
        Assert.Null(protector.Unprotect(KeychainApiKeyProtector.Prefix + "not base64!"));
        Assert.Null(protector.Unprotect(string.Empty));
    }

    [Fact]
    public void Unprotect_with_another_key_returns_null()
    {
        var sealedText = new KeychainApiKeyProtector(new MemoryKeyStore()).Protect("secret");
        Assert.Null(new KeychainApiKeyProtector(new MemoryKeyStore()).Unprotect(sealedText));
    }

    [Fact]
    public void Protect_refuses_when_the_keychain_refuses()
    {
        var protector = new KeychainApiKeyProtector(new MemoryKeyStore { Refuse = true });
        Assert.Throws<System.Security.Cryptography.CryptographicException>(() => protector.Protect("secret"));
    }

    [Fact]
    public void Protect_uses_a_key_stored_concurrently_by_another_instance()
    {
        var store = new MemoryKeyStore { Refuse = true, Preloaded = new byte[32] };
        store.HideUntilRefused = true;
        var protector = new KeychainApiKeyProtector(store);

        var sealedText = protector.Protect("secret");
        Assert.Equal("secret", protector.Unprotect(sealedText));
    }

    private sealed class MemoryKeyStore : ISecretKeyStore
    {
        private byte[]? _key;

        public bool Refuse { get; init; }

        public byte[]? Preloaded { get; init; }

        public bool HideUntilRefused { get; set; }

        public int Saves { get; private set; }

        public byte[]? Load()
        {
            if (HideUntilRefused)
            {
                return null;
            }

            return _key ?? Preloaded;
        }

        public bool Save(byte[] key)
        {
            if (Refuse)
            {
                HideUntilRefused = false;
                return false;
            }

            Saves++;
            _key = key;
            return true;
        }
    }
}

public sealed class MacAutostartServiceTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "axiom-autostart-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void Enable_writes_a_launch_agent_with_autostart_and_disable_removes_it()
    {
        const string executable = "/Applications/Axiom.app/Contents/MacOS/Axiom";
        var service = new MacAutostartService(executable, _directory);

        Assert.False(service.IsEnabled);
        Assert.True(service.SetEnabled(true));
        Assert.True(service.IsEnabled);
        Assert.False(service.CanRepair);
        Assert.Equal("Autostart: active (login item)", service.StatusText);

        var plist = File.ReadAllText(service.PlistPath);
        Assert.Contains("<string>com.axiom.firewall.agent</string>", plist, StringComparison.Ordinal);
        Assert.Contains("<string>--autostart</string>", plist, StringComparison.Ordinal);
        Assert.Contains("<string>Aqua</string>", plist, StringComparison.Ordinal);
        Assert.EndsWith("com.axiom.firewall.agent.plist", service.PlistPath, StringComparison.Ordinal);

        Assert.True(service.SetEnabled(false));
        Assert.False(File.Exists(service.PlistPath));
        Assert.Equal("Autostart: off", service.StatusText);
    }

    [Fact]
    public void A_moved_app_is_reported_stale_and_repair_rewrites_the_path()
    {
        new MacAutostartService("/Users/me/Downloads/Axiom.app/Contents/MacOS/Axiom", _directory).SetEnabled(true);
        var service = new MacAutostartService("/Applications/Axiom.app/Contents/MacOS/Axiom", _directory);

        Assert.True(service.IsEnabled);
        Assert.True(service.CanRepair);
        Assert.True(service.Repair());
        Assert.False(service.CanRepair);
    }

    [Fact]
    public void Plist_escapes_xml_in_the_path()
    {
        var plist = MacAutostartService.BuildPlist("/Apps/A&B <x>.app/Contents/MacOS/Axiom");
        Assert.Contains("A&amp;B &lt;x&gt;", plist, StringComparison.Ordinal);
        Assert.Equal("/Apps/A&B <x>.app/Contents/MacOS/Axiom", MacAutostartService.ReadProgram(plist));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}

public sealed class FilterExtensionStatusTests
{
    [Fact]
    public void Parses_running_status()
    {
        const string json = """{"appBundle":"/Applications/Axiom.app","command":"status","exitCode":0,"filter":{"configured":true,"enabled":true},"ok":true,"state":"running"}""";
        var status = FilterExtensionStatus.Parse("status", 0, json);

        Assert.True(status.Ok);
        Assert.True(status.IsRunning);
        Assert.True(status.FilterConfigured);
        Assert.False(status.NeedsApproval);
        Assert.Equal("The Axiom network filter is running.", status.Summary);
    }

    [Fact]
    public void Exit_code_three_means_approval_with_settings_guidance()
    {
        const string json = """{"command":"activate","exitCode":3,"ok":false,"state":"needs_approval"}""";
        var status = FilterExtensionStatus.Parse("activate", 3, json);

        Assert.True(status.NeedsApproval);
        Assert.False(status.IsRunning);
        Assert.Contains("Login Items & Extensions > Network Extensions", status.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Reboot_and_error_messages_are_surfaced()
    {
        Assert.True(FilterExtensionStatus.Parse("activate", 4, """{"state":"reboot_required","ok":false}""").NeedsReboot);

        var error = FilterExtensionStatus.Parse(
            "activate",
            1,
            """{"ok":false,"state":"error","error":{"domain":"OSSystemExtensionErrorDomain","code":3,"message":"App must be in /Applications"}}""");
        Assert.Equal("App must be in /Applications", error.Message);
        Assert.Equal("App must be in /Applications", error.Summary);
    }

    [Fact]
    public void Garbage_output_is_an_error_not_a_crash()
    {
        Assert.Equal("error", FilterExtensionStatus.Parse("status", 1, "boom").State);
        Assert.Equal("error", FilterExtensionStatus.Parse("status", 1, "{not json}").State);
        Assert.False(FilterExtensionStatus.Parse("status", 0, string.Empty).Ok);
    }

    [Fact]
    public void Progress_lines_before_the_json_are_ignored()
    {
        var status = FilterExtensionStatus.Parse(
            "status",
            0,
            "waiting...\n{\"state\":\"installed_filter_disabled\",\"ok\":true,\"filter\":{\"configured\":true,\"enabled\":false}}\n");
        Assert.Equal("installed_filter_disabled", status.State);
        Assert.False(status.IsRunning);
        Assert.Equal("The Axiom network filter is installed but turned off.", status.Summary);
    }
}

public sealed class MacHostHelperTests
{
    [Fact]
    public void Daemon_state_classification()
    {
        Assert.Equal(DaemonState.Running, MacProtectionSetup.Classify(connected: true, installed: false));
        Assert.Equal(DaemonState.InstalledNotResponding, MacProtectionSetup.Classify(connected: false, installed: true));
        Assert.Equal(DaemonState.NotInstalled, MacProtectionSetup.Classify(connected: false, installed: false));
    }

    [Fact]
    public void Rendering_defaults_to_gpu_with_software_fallback_and_honours_override()
    {
        Assert.Equal(
            [AvaloniaNativeRenderingMode.Metal, AvaloniaNativeRenderingMode.OpenGl, AvaloniaNativeRenderingMode.Software],
            Program.RenderingModes(null));
        Assert.Equal([AvaloniaNativeRenderingMode.Software], Program.RenderingModes(" software "));
        Assert.Equal(AvaloniaNativeRenderingMode.Software, Program.RenderingModes("opengl")[^1]);
    }

    [Fact]
    public void Theme_follows_apple_interface_style()
    {
        Assert.Equal(UiTheme.Dark, MacThemeService.FromAppleInterfaceStyle(0, "Dark\n"));
        Assert.Equal(UiTheme.Light, MacThemeService.FromAppleInterfaceStyle(1, string.Empty));
        Assert.Equal(UiTheme.Light, MacThemeService.FromPlatform(PlatformThemeVariant.Light));
        Assert.Equal(UiTheme.Dark, MacThemeService.FromPlatform(PlatformThemeVariant.Dark));
    }

    [Fact]
    public void Relaunch_command_quotes_bundle_and_arguments()
    {
        var command = AvaloniaShellActions.BuildRelaunchCommand(
            "/Applications/Ax'iom.app",
            "/Applications/Ax'iom.app/Contents/MacOS/Axiom",
            ["--start-minimized"]);
        Assert.Equal("sleep 2; /usr/bin/open -n '/Applications/Ax'\\''iom.app' --args '--start-minimized'", command);
        Assert.Null(AvaloniaShellActions.BuildRelaunchCommand(null, null, []));
    }

    [Fact]
    public async Task Dns_helper_explains_instead_of_pretending()
    {
        var helper = new MacDnsAdapterHelper();
        var exception = await Assert.ThrowsAsync<NotSupportedException>(
            () => helper.EnableAsync("Wi-Fi", "127.0.0.1", CancellationToken.None));
        Assert.Contains("automatically", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Single_instance_second_acquire_fails_and_signal_reaches_the_first()
    {
        var directory = Path.Combine(Path.GetTempPath(), "axs-" + Guid.NewGuid().ToString("N")[..8]);
        using var first = new MacSingleInstance(directory);
        Assert.True(first.TryAcquire());
        using var shown = new ManualResetEventSlim();
        first.Listen(shown.Set);

        using var second = new MacSingleInstance(directory);
        Assert.False(second.TryAcquire());
        Assert.True(second.SignalExisting());
        Assert.True(shown.Wait(TimeSpan.FromSeconds(5)));

        first.Dispose();
        using var third = new MacSingleInstance(directory);
        Assert.True(third.TryAcquire());
        Directory.Delete(directory, recursive: true);
    }
}
