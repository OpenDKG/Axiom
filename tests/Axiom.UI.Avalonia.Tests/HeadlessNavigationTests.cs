// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Controls;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class HeadlessNavigationTests
{
    [Fact]
    public void Main_window_navigates_through_every_page_without_a_render_error()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var shell = new ShellViewModel(new FakeSource(), new FakeTimerFactory());
            var window = new MainWindow { DataContext = shell };
            window.Show();
            Dispatcher.UIThread.RunJobs();

            Assert.Equal(12, shell.Pages.Count);
            Assert.IsType<AgentDashboardPageViewModel>(shell.Pages[0]);
            Assert.NotNull(shell.OpenContactCommand);
            var contactButton = window.GetVisualDescendants()
                .OfType<Button>()
                .FirstOrDefault(button => string.Equals(button.Content as string, "Contact", StringComparison.Ordinal));
            Assert.NotNull(contactButton);
            foreach (var page in shell.Pages)
            {
                shell.SelectedPage = page;
                Dispatcher.UIThread.RunJobs();
                Assert.Same(page, shell.SelectedPage);
            }

            window.Close();
            shell.Dispose();
        });
    }

    [Fact]
    public void Tray_mode_stops_the_ui_traffic_timer_and_keeps_the_connection_monitor_running()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var timers = new FakeTimerFactory();
            using var shell = new ShellViewModel(new FakeSource(), timers);
            shell.Start();
            var monitorTimer = timers.Created[0];
            var trafficTimer = timers.Created[1];
            Assert.True(monitorTimer.IsEnabled);
            Assert.True(trafficTimer.IsEnabled);

            shell.SetPresentationVisible(false);
            Assert.True(monitorTimer.IsEnabled);
            Assert.False(trafficTimer.IsEnabled);

            shell.SetPresentationVisible(true);
            Assert.True(monitorTimer.IsEnabled);
            Assert.True(trafficTimer.IsEnabled);
        });
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

    private sealed class FakeTimerFactory : IUiTimerFactory
    {
        public List<IUiTimer> Created { get; } = [];

        public IUiTimer Create(TimeSpan interval)
        {
            var timer = new FakeTimer(interval);
            Created.Add(timer);
            return timer;
        }

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
