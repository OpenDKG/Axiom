// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Threading;
using Axiom.Presentation;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class MainWindowLayoutTests
{
    [Theory]
    // 1280x800 must not open the 1460x900 default partly off-screen.
    [InlineData(1280, 800, 1.0, 1280, 800, 0, 0)]
    // A smaller screen stays on-screen even below the preferred minimum.
    [InlineData(800, 600, 1.0, 800, 600, 0, 0)]
    // A normal desktop keeps the preferred size, centered.
    [InlineData(1920, 1080, 1.0, 1460, 900, 230, 90)]
    // Work area offsets (taskbar) are honored.
    [InlineData(1280, 760, 1.0, 1280, 760, 0, 0)]
    // HiDPI: physical 2560x1600 is only 1280x800 device-independent pixels.
    [InlineData(2560, 1600, 2.0, 1280, 800, 0, 0)]
    public void Startup_window_fits_the_working_area(
        int areaWidth,
        int areaHeight,
        double scaling,
        double expectedWidth,
        double expectedHeight,
        int expectedX,
        int expectedY)
    {
        var (width, height, position) = MainWindow.FitToWorkingArea(
            1460, 900, 900, 600, new PixelRect(0, 0, areaWidth, areaHeight), scaling);

        Assert.Equal(expectedWidth, width);
        Assert.Equal(expectedHeight, height);
        Assert.Equal(new PixelPoint(expectedX, expectedY), position);
    }

    [Fact]
    public void Startup_window_is_placed_inside_an_offset_working_area()
    {
        // e.g. a top panel: the window must start at the work-area origin, not -90,-50.
        var (width, height, position) = MainWindow.FitToWorkingArea(
            1460, 900, 900, 600, new PixelRect(0, 40, 1280, 760), 1.0);

        Assert.Equal(1280, width);
        Assert.Equal(760, height);
        Assert.Equal(new PixelPoint(0, 40), position);
    }

    [Fact]
    public void Main_window_opens_inside_the_primary_working_area()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var shell = new ShellViewModel(new FakeSource(), new FakeTimerFactory());
            var window = new MainWindow { DataContext = shell };
            window.Show();
            Dispatcher.UIThread.RunJobs();

            var screen = window.Screens.Primary;
            Assert.NotNull(screen);
            var area = screen.WorkingArea;
            Assert.True(window.Width <= (area.Width / screen.Scaling) + 0.5);
            Assert.True(window.Height <= (area.Height / screen.Scaling) + 0.5);
            Assert.True(window.Position.X >= area.X);
            Assert.True(window.Position.Y >= area.Y);
            Assert.True(window.Position.X + (window.Width * screen.Scaling) <= area.Right + 1);
            Assert.True(window.Position.Y + (window.Height * screen.Scaling) <= area.Bottom + 1);

            window.Close();
            shell.Dispose();
        });
    }

    private sealed class FakeSource : Axiom.Contracts.Monitoring.IConnectionSnapshotSource
    {
        public string Name => "test";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<Axiom.Contracts.Monitoring.ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new Axiom.Contracts.Monitoring.ConnectionSnapshot
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
