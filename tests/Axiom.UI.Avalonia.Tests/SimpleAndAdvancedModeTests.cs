// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Avalonia.Controls;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;
using Axiom.UI.Avalonia.Views;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class SimpleAndAdvancedModeTests : IDisposable
{
    private readonly DirectoryInfo _tempDir =
        Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"axiom-ui-mode-{Guid.NewGuid():N}"));

    public void Dispose()
    {
        if (_tempDir.Exists)
        {
            _tempDir.Delete(recursive: true);
        }
    }

    [Fact]
    public void UiModeSettingsStore_defaults_to_simple_and_persists_round_trip()
    {
        var path = Path.Combine(_tempDir.FullName, "ui-mode.txt");
        Assert.Equal(UiMode.Simple, UiModeSettingsStore.Load(path));

        UiModeSettingsStore.Save(UiMode.Advanced, path);
        Assert.Equal(UiMode.Advanced, UiModeSettingsStore.Load(path));

        UiModeSettingsStore.Save(UiMode.Simple, path);
        Assert.Equal(UiMode.Simple, UiModeSettingsStore.Load(path));
    }

    [Fact]
    public void Titlebar_switch_toggles_between_simple_and_advanced_modes_and_renders_cleanly()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var modeService = new FixedUiModeService(UiMode.Simple);
            var shell = new ShellViewModel(
                new FakeSource(),
                new FakeTimerFactory(),
                uiModeService: modeService);
            var window = new MainWindow { DataContext = shell };
            window.Show();
            Dispatcher.UIThread.RunJobs();

            var simpleBtn = window.FindControl<Button>("SimpleModeButton");
            var advancedBtn = window.FindControl<Button>("AdvancedModeButton");
            Assert.NotNull(simpleBtn);
            Assert.NotNull(advancedBtn);
            Assert.True(simpleBtn.IsVisible);
            Assert.True(advancedBtn.IsVisible);

            // Starts in Simple mode cleanly with 5 essential navigation items
            Assert.True(shell.IsSimpleMode);
            Assert.False(shell.IsAdvancedMode);
            Assert.Equal(5, shell.NavigationPages.Count);
            Assert.Same(shell.SimpleHome, shell.SelectedPage);
            Assert.Contains(window.GetVisualDescendants(), v => v is SimpleHomeView);

            // Switch to Advanced mode -> shows full 12 pages and returns from SimpleHome to AgentDashboard
            shell.SwitchToAdvancedModeCommand.Execute(null);
            Dispatcher.UIThread.RunJobs();
            Assert.True(shell.IsAdvancedMode);
            Assert.Equal(12, shell.NavigationPages.Count);
            Assert.Same(shell.AgentDashboard, shell.SelectedPage);

            // Move to an Advanced-only page, then switch back to Simple -> cleanly falls back to SimpleHome
            shell.SelectedPage = shell.AgentStats;
            Dispatcher.UIThread.RunJobs();
            shell.SwitchToSimpleModeCommand.Execute(null);
            Dispatcher.UIThread.RunJobs();
            Assert.True(shell.IsSimpleMode);
            Assert.Equal(5, shell.NavigationPages.Count);
            Assert.Same(shell.SimpleHome, shell.SelectedPage);

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
