// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class AvaloniaPageTests
{
    [Fact]
    public void Shell_exposes_all_eleven_parity_pages()
    {
        var shell = new ShellViewModel(new FakeSource(), new FakeTimerFactory());

        Assert.Equal(11, shell.Pages.Count);
        Assert.Contains(shell.Pages, page => page.Title == "Security");
        Assert.Contains(shell.Pages, page => page.Title == "Agents");
        Assert.False(shell.IsServiceMode);

        shell.Dispose();
    }

    [Fact]
    public void Events_page_requires_the_service_instead_of_generating_rows()
    {
        var page = new EventsPageViewModel(null, new FakeTimerFactory(), new NullUserInteraction());

        Assert.True(page.IsEmpty);
        Assert.Contains("local service", page.StatusText, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(page.Rows);

        page.Dispose();
    }

    [Fact]
    public void Privacy_shield_reports_service_required_without_changing_dns()
    {
        var page = new PrivacyShieldPageViewModel(
            null,
            new NullUserInteraction(),
            new UnsupportedDnsAdapterHelper(),
            new FakeTimerFactory());

        Assert.False(page.IsSupported);
        Assert.Equal("SERVICE REQUIRED", page.StatusBadge);
        Assert.Contains("No DNS settings were changed", page.DetailText);

        page.Dispose();
    }

    [Fact]
    public async Task Firewall_page_reports_an_offline_service()
    {
        var page = new FirewallPageViewModel(new OfflineClient(), new NullUserInteraction());

        await Task.Delay(200);

        Assert.Equal("Service offline", page.CapabilityStatusText);
        Assert.True(page.IsEmpty);
        Assert.False(page.WritesEnabled);
        Assert.Empty(page.Rules);
    }

    private sealed class FakeSource : IConnectionSnapshotSource
    {
        public string Name => "test";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UtcNow,
                Connections = [],
                ProcessCount = 0,
                SourceName = "test",
            });
    }

    private sealed class OfflineClient : IServiceRequestClient
    {
        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken) =>
            throw new ServiceUnavailableException(IpcErrorCodes.ServiceUnavailable, "offline");
    }

    private sealed class FakeTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new FakeTimer(interval);

        private sealed class FakeTimer(TimeSpan interval) : IUiTimer
        {
            public TimeSpan Interval { get; set; } = interval;

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
