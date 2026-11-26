// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Threading;
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// Simple and Mini surfaces may open a page outside their sidebar, but must keep a direct return
/// path and must not persist Advanced mode just because the user looked at an advanced page.
/// </summary>
public sealed class SimpleMiniNavigationTests
{
    [Fact]
    public async Task Configure_from_simple_privacy_keeps_mode_highlight_and_back_path()
    {
        await Dispatcher.UIThread.InvokeAsync(async () =>
        {
            var mode = new FixedUiModeService(UiMode.Simple);
            using var shell = NewShell(mode);
            shell.SelectedPage = shell.PrivacyOverview;
            shell.PrivacyOverview.OpenSettingsCommand.Execute(null);

            Assert.Same(shell.PrivacyShield, shell.SelectedPage);
            Assert.Equal(UiMode.Simple, mode.Current);
            Assert.True(shell.HasContextualReturn);
            Assert.Same(shell.PrivacyOverview, shell.SelectedNavigationPage);
            Assert.Contains(shell.NavigationPages, page => ReferenceEquals(page, shell.PrivacyOverview));

            shell.GoBackCommand.Execute(null);
            Assert.Same(shell.PrivacyOverview, shell.SelectedPage);
            Assert.False(shell.HasContextualReturn);
            Assert.Equal(UiMode.Simple, mode.Current);
            await Task.CompletedTask;
        });
    }

    [Fact]
    public async Task Simple_deep_links_do_not_persist_advanced_and_return_to_simple_home()
    {
        await Dispatcher.UIThread.InvokeAsync(async () =>
        {
            var mode = new FixedUiModeService(UiMode.Simple);
            using var shell = NewShell(mode);

            shell.SimpleHome.OpenNetworkAdvancedCommand.Execute(null);
            Assert.Same(shell.Overview, shell.SelectedPage);
            Assert.Equal(UiMode.Simple, mode.Current);
            Assert.Same(shell.SimpleHome, shell.SelectedNavigationPage);
            shell.GoBackCommand.Execute(null);
            Assert.Same(shell.SimpleHome, shell.SelectedPage);

            shell.SimpleHome.OpenAgentsCommand.Execute(null);
            Assert.Same(shell.Agents, shell.SelectedPage);
            Assert.Equal(UiMode.Simple, mode.Current);
            shell.GoBackCommand.Execute(null);
            Assert.Same(shell.SimpleHome, shell.SelectedPage);
            Assert.Equal(UiMode.Simple, mode.Current);
            await Task.CompletedTask;
        });
    }

    [Fact]
    public async Task Mini_network_overview_opens_overview_and_returns_to_mini()
    {
        await Dispatcher.UIThread.InvokeAsync(async () =>
        {
            var mode = new FixedUiModeService(UiMode.Mini);
            using var shell = NewShell(mode);
            Assert.Same(shell.MiniHome, shell.SelectedPage);

            shell.MiniHome.OpenNetworkOverviewCommand.Execute(null);
            Assert.Same(shell.Overview, shell.SelectedPage);
            Assert.NotSame(shell.Firewall, shell.SelectedPage);
            Assert.Equal(UiMode.Mini, mode.Current);
            Assert.Same(shell.MiniHome, shell.SelectedNavigationPage);

            shell.GoBackCommand.Execute(null);
            Assert.Same(shell.MiniHome, shell.SelectedPage);
            Assert.False(shell.HasContextualReturn);

            shell.MiniHome.OpenAgentsCommand.Execute(null);
            Assert.Same(shell.Agents, shell.SelectedPage);
            Assert.Equal(UiMode.Mini, mode.Current);
            shell.GoBackCommand.Execute(null);
            Assert.Same(shell.MiniHome, shell.SelectedPage);
            Assert.Equal(UiMode.Mini, mode.Current);
            await Task.CompletedTask;
        });
    }

    private static ShellViewModel NewShell(IUiModeService mode) =>
        new(new EmptySource(), new NoopTimerFactory(), uiModeService: mode);

    private sealed class EmptySource : IConnectionSnapshotSource
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

    private sealed class NoopTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new NoopTimer(interval);

        private sealed class NoopTimer(TimeSpan interval) : IUiTimer
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
