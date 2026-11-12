// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class NetworkRecoverySettingsTests
{
    [Fact]
    public async Task Restore_reports_verified_success_from_the_service()
    {
        var page = Create(new NetworkRecoveryRestoreResult
        {
            Status = NetworkRecoveryStatus.Succeeded,
            AdaptersRestored = 2,
            AdaptersVerified = 2,
            RulesRemoved = 1,
            Verified = true,
        });

        await page.RestoreNetworkSettingsCommand.ExecuteAsync(null);

        Assert.Contains("Restored and verified 2 adapter(s)", page.NetworkRecoveryStatusText, StringComparison.Ordinal);
        Assert.Contains("removed 1 Axiom-owned rule(s)", page.NetworkRecoveryStatusText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Restore_reports_a_missing_snapshot_without_claiming_a_change()
    {
        var page = Create(new NetworkRecoveryRestoreResult
        {
            Status = NetworkRecoveryStatus.NoSnapshot,
        });

        await page.RestoreNetworkSettingsCommand.ExecuteAsync(null);

        Assert.Contains("Nothing was changed", page.NetworkRecoveryStatusText, StringComparison.Ordinal);
        Assert.DoesNotContain("Restored", page.NetworkRecoveryStatusText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Restore_surfaces_an_unexpected_local_failure_truthfully()
    {
        var page = Create(exception: new UnauthorizedAccessException("denied"));

        await page.RestoreNetworkSettingsCommand.ExecuteAsync(null);

        Assert.Contains("Restore failed before it could complete", page.NetworkRecoveryStatusText, StringComparison.Ordinal);
    }

    [Fact]
    public void Restore_is_hidden_when_the_host_has_no_service_client()
    {
        var page = CreatePage(restore: null);

        Assert.False(page.HasNetworkRecovery);
        page.Dispose();
    }

    private static SettingsPageViewModel Create(
        NetworkRecoveryRestoreResult? result = null,
        Exception? exception = null)
    {
        var page = CreatePage(async _ =>
        {
            await Task.Yield();
            if (exception is not null)
            {
                throw exception;
            }

            return result ?? new NetworkRecoveryRestoreResult
            {
                Status = NetworkRecoveryStatus.Failed,
            };
        });
        return page;
    }

    private static SettingsPageViewModel CreatePage(
        Func<CancellationToken, Task<NetworkRecoveryRestoreResult>>? restore)
    {
        var monitor = new ConnectionMonitor(new FakeSource(), new NoOpTimerFactory());
        return new SettingsPageViewModel(
            monitor,
            serviceMode: true,
            theme: new FixedThemeService(),
            autostart: new UnsupportedAutostartService(),
            restoreNetwork: restore);
    }

    private sealed class FakeSource : IConnectionSnapshotSource
    {
        public string Name => "demo";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UtcNow,
                Connections = [],
                ProcessCount = 0,
                SourceName = "demo",
            });
    }

    private sealed class NoOpTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new NoOpTimer();

        private sealed class NoOpTimer : IUiTimer
        {
            public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(1);

            public bool IsEnabled { get; private set; }

            public event EventHandler? Tick
            {
                add { }
                remove { }
            }

            public void Start() => IsEnabled = true;

            public void StopTimer() => IsEnabled = false;

            public void Dispose()
            {
            }
        }
    }
}
