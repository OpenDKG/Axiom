// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Privacy;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class PrivacyShieldHistoryTests
{
    [Fact]
    public async Task Expanded_history_app_stays_open_across_refreshes()
    {
        var client = new PrivacyShieldClient(Status(secondApp: false));
        var page = CreatePage(client);
        try
        {
            await page.RefreshCommand.ExecuteAsync(null);

            var group = Assert.Single(page.BlockedHistoryGroups);
            group.IsExpanded = true;

            await page.RefreshCommand.ExecuteAsync(null);

            Assert.Same(group, page.BlockedHistoryGroups[0]);
            Assert.True(page.BlockedHistoryGroups[0].IsExpanded);
        }
        finally
        {
            page.Dispose();
        }
    }

    [Fact]
    public async Task Expanded_history_app_stays_open_when_new_blocks_arrive()
    {
        var client = new PrivacyShieldClient(Status(secondApp: false));
        var page = CreatePage(client);
        try
        {
            await page.RefreshCommand.ExecuteAsync(null);

            var browser = page.BlockedHistoryGroups.First(group => group.AppDisplay == "browser.exe");
            browser.IsExpanded = true;

            client.Status = Status(secondApp: true);
            await page.RefreshCommand.ExecuteAsync(null);

            var refreshed = page.BlockedHistoryGroups.First(group => group.AppDisplay == "browser.exe");
            Assert.True(refreshed.IsExpanded);
            Assert.False(page.BlockedHistoryGroups.First(group => group.AppDisplay == "Second.exe").IsExpanded);
        }
        finally
        {
            page.Dispose();
        }
    }

    [Fact]
    public async Task Collapsed_history_app_stays_collapsed()
    {
        var client = new PrivacyShieldClient(Status(secondApp: false));
        var page = CreatePage(client);
        try
        {
            await page.RefreshCommand.ExecuteAsync(null);

            var group = Assert.Single(page.BlockedHistoryGroups);
            group.IsExpanded = true;
            group.IsExpanded = false;

            await page.RefreshCommand.ExecuteAsync(null);

            Assert.False(page.BlockedHistoryGroups[0].IsExpanded);
        }
        finally
        {
            page.Dispose();
        }
    }

    private static PrivacyShieldPageViewModel CreatePage(IServiceRequestClient client) =>
        new(client, new NullUserInteraction(), new UnsupportedDnsAdapterHelper(), new NoOpTimerFactory());

    private static PrivacyShieldStatus Status(bool secondApp)
    {
        var now = DateTimeOffset.UtcNow;
        var history = new List<PrivacyShieldBlockedEvent>
        {
            new("doubleclick.net", PrivacyCategory.Ads, now) { AppName = "browser.exe", AppPath = @"C:\browser.exe" },
            new("google-analytics.com", PrivacyCategory.Analytics, now.AddMinutes(-1))
            {
                AppName = "browser.exe",
                AppPath = @"C:\browser.exe",
            },
        };

        if (secondApp)
        {
            history.Insert(0, new PrivacyShieldBlockedEvent("ads.example", PrivacyCategory.Ads, now)
            {
                AppName = "Second.exe",
                AppPath = @"C:\Second.exe",
            });
        }

        return new PrivacyShieldStatus
        {
            State = "Active",
            Enabled = true,
            Running = true,
            Port = 53,
            BindAddress = "127.0.0.1, ::1",
            Upstream = "192.168.0.1:53",
            Queries = 10,
            Allowed = 7,
            Blocked = 3,
            Errors = 0,
            RuleCount = 120,
            Settings = new PrivacyShieldSettings { Enabled = true },
            BlockedHistory = history,
        };
    }

    private sealed class PrivacyShieldClient(PrivacyShieldStatus status) : IServiceRequestClient
    {
        public PrivacyShieldStatus Status { get; set; } = status;

        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            if (command != IpcCommandTypes.PrivacyStatus)
            {
                throw new ServiceUnavailableException(IpcErrorCodes.NotSupported, "not supported");
            }

            return Task.FromResult((T)(object)Status);
        }
    }

    private sealed class NoOpTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new NoOpTimer();

        private sealed class NoOpTimer : IUiTimer
        {
            public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(2);

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
