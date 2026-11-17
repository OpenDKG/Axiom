// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Sockets;
using Axiom.Contracts.Privacy;
using Axiom.Service.Hosting.Dns;
using Xunit;

namespace Axiom.Service.Tests;

/// <summary>
/// Maintainer decision (#441/#274): a system-DNS (adapter) error from the platform seam
/// <see cref="IPrivacyDnsPlatform"/> reaches the Privacy Shield status truthfully, and turning the
/// shield off runs the platform's DNS recovery. Uses a fake platform: no system DNS is touched.
/// </summary>
public sealed class PrivacyDnsPlatformErrorTests
{
    [Fact]
    public async Task Redirect_error_from_the_platform_is_reported_in_the_status()
    {
        var platform = new FakeDnsPlatform { StartResult = "Wi-Fi: networksetup -setdnsservers failed (exit 4)" };
        var status = await RunEnabledAsync(platform);

        Assert.True(status.Running);
        Assert.Contains("networksetup -setdnsservers failed", status.LastError, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Redirect_exception_from_the_platform_is_reported_not_swallowed()
    {
        var platform = new FakeDnsPlatform { StartThrows = true };
        var status = await RunEnabledAsync(platform);

        Assert.True(status.Running);
        Assert.Contains("System DNS could not be pointed at the resolver", status.LastError, StringComparison.Ordinal);
        Assert.Contains("scutil unavailable", status.LastError, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Turning_the_shield_off_runs_the_platform_dns_recovery()
    {
        var platform = new FakeDnsPlatform();
        var directory = Directory.CreateTempSubdirectory("axiom-dnsplat-");
        try
        {
            await using var controller = NewController(directory.FullName, platform);
            var on = await controller.ConfigureAsync(Settings(ReservePort(), enabled: true), CancellationToken.None);
            Assert.True(on.Running);

            var off = await controller.ConfigureAsync(Settings(on.Settings.Port, enabled: false), CancellationToken.None);
            Assert.False(off.Running);

            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (platform.RestoreCalls == 0 && DateTime.UtcNow < deadline)
            {
                await Task.Delay(20);
            }

            Assert.True(platform.RestoreCalls > 0, "disabling must restore system DNS through the platform seam");
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// Windows adapter DNS (upstream v0.64.0): when automatic adapter DNS setup fails, the error the
    /// platform returns from <see cref="IPrivacyDnsPlatform.EnsureConfiguredAdapterDns"/> becomes the
    /// status error while the resolver keeps running.
    /// </summary>
    [Fact]
    public async Task Adapter_dns_error_from_the_platform_is_reported_in_the_status()
    {
        var platform = new FakeDnsPlatform { AdapterError = "Adapter 'Ethernet' has no valid IPv4 fallback DNS/gateway yet." };
        var status = await RunEnabledAsync(platform);

        Assert.True(status.Running);
        Assert.Equal("Adapter 'Ethernet' has no valid IPv4 fallback DNS/gateway yet.", status.LastError);
        Assert.True(platform.AdapterCalls > 0);
    }

    /// <summary>Upstream applies the adapter error only when no other error is set; the seam keeps that.</summary>
    [Fact]
    public async Task Adapter_dns_error_does_not_replace_an_earlier_error()
    {
        var platform = new FakeDnsPlatform
        {
            StartResult = "redirect warning",
            AdapterError = "Adapter 'Ethernet' has no valid IPv4 fallback DNS/gateway yet.",
        };
        var status = await RunEnabledAsync(platform);

        Assert.True(status.Running);
        Assert.Equal("redirect warning", status.LastError);
    }

    /// <summary>
    /// A shield that cannot start (port already taken) must not leave the system pointed at a dead
    /// loopback resolver: the controller reports the error and runs the platform's recovery.
    /// </summary>
    [Fact]
    public async Task Failed_start_reports_the_error_and_runs_the_platform_dns_recovery()
    {
        var directory = Directory.CreateTempSubdirectory("axiom-dnsplat-");
        try
        {
            int port;
            await using (var first = NewController(directory.FullName, new FakeDnsPlatform()))
            {
                var on = await first.ConfigureAsync(Settings(ReservePort(), enabled: true), CancellationToken.None);
                Assert.True(on.Running);
                port = on.Settings.Port;
            }

            using var squatter = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
            var platform = new FakeDnsPlatform();
            await using var restarted = NewController(directory.FullName, platform);
            await restarted.StartAsync(CancellationToken.None);
            var status = await restarted.GetStatusAsync(CancellationToken.None);

            Assert.False(status.Running);
            Assert.False(string.IsNullOrWhiteSpace(status.LastError));
            await WaitForRestoreAsync(platform);
            Assert.True(platform.RestoreCalls > 0, "a failed start must restore system DNS through the platform seam");
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// Service start with the shield off restores DNS first (recovery ownership stays with the
    /// service, through the platform seam), and starts no resolver.
    /// </summary>
    [Fact]
    public async Task Worker_start_with_the_shield_off_runs_the_platform_dns_recovery()
    {
        var directory = Directory.CreateTempSubdirectory("axiom-dnsplat-");
        try
        {
            var platform = new FakeDnsPlatform();
            await using var controller = NewController(directory.FullName, platform);
            using var worker = new PrivacyShieldWorker(controller, platform);
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            await worker.StartAsync(stop.Token);
            await WaitForRestoreAsync(platform);
            await worker.StopAsync(CancellationToken.None);

            Assert.True(platform.RestoreCalls > 0, "service start with the shield off must restore DNS");
            Assert.False(controller.IsResolverRunning);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static async Task WaitForRestoreAsync(FakeDnsPlatform platform)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (platform.RestoreCalls == 0 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }
    }

    private static async Task<PrivacyShieldStatus> RunEnabledAsync(FakeDnsPlatform platform)
    {
        var directory = Directory.CreateTempSubdirectory("axiom-dnsplat-");
        try
        {
            await using var controller = NewController(directory.FullName, platform);
            return await controller.ConfigureAsync(Settings(ReservePort(), enabled: true), CancellationToken.None);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static PrivacyShieldController NewController(string directory, IPrivacyDnsPlatform platform) => new(
        new PrivacyShieldSettingsStore(Path.Combine(directory, "privacy-shield.json")),
        new PrivacyShieldRuleStore(Path.Combine(directory, "rules.bin")),
        dnsPlatform: platform);

    private static PrivacyShieldSettings Settings(int port, bool enabled) => new()
    {
        Enabled = enabled,
        Port = port,
        Categories = PrivacyCategory.None,
        BlockedDomains = ["blocked.example"],
        UpstreamDns = "1.1.1.1",
    };

    private static int ReservePort()
    {
        using var probe = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.Client.LocalEndPoint!).Port;
    }

    private sealed class FakeDnsPlatform : IPrivacyDnsPlatform
    {
        public string? StartResult { get; init; }

        public bool StartThrows { get; init; }

        public string? AdapterError { get; init; }

        private int _adapterCalls;

        public int AdapterCalls => Volatile.Read(ref _adapterCalls);

        public string? EnsureConfiguredAdapterDns(bool resolverRunning, PrivacyShieldSettings settings)
        {
            Interlocked.Increment(ref _adapterCalls);
            return resolverRunning ? AdapterError : null;
        }

        private int _restoreCalls;

        public int RestoreCalls => Volatile.Read(ref _restoreCalls);

        public IDnsAppAttributor? Attributor => null;

        public string NoUpstreamWarning => "none";

        public IReadOnlyList<IPEndPoint> DiscoverUpstreams() => [];

        public string? OnResolverStarted(int port) =>
            StartThrows ? throw new InvalidOperationException("scutil unavailable") : StartResult;

        public bool RestoreIfNeeded()
        {
            Interlocked.Increment(ref _restoreCalls);
            return true;
        }
    }
}
