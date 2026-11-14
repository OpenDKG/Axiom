// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Threading;
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

            Assert.Equal(14, shell.Pages.Count);
            Assert.IsType<AgentDashboardPageViewModel>(shell.Pages[0]);
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
