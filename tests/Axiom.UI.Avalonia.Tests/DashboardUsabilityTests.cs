// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;
using Axiom.UI.Avalonia.Controls;
using Axiom.UI.Avalonia.Views;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class DashboardUsabilityTests
{
    [Fact]
    public void Main_window_removes_top_right_local_first_label_and_uses_selectable_status_text()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            using var shell = new ShellViewModel(new ScriptedSource(EmptySnapshot()), new FakeTimerFactory());
            var window = new MainWindow { Width = 1200, Height = 800, DataContext = shell };

            try
            {
                window.Show();
                Dispatcher.UIThread.RunJobs();

                var exactLocalFirst = window.GetVisualDescendants()
                    .OfType<TextBlock>()
                    .Where(tb => string.Equals(tb.Text, "LOCAL-FIRST", StringComparison.Ordinal))
                    .ToList();
                Assert.Empty(exactLocalFirst);

                Assert.IsType<AxiomSelectableTextBlock>(window.FindControl<TextBlock>("HeaderPageTitle"));
                Assert.IsType<AxiomSelectableTextBlock>(window.FindControl<TextBlock>("HeaderPageSubtitle"));
            }
            finally
            {
                window.Close();
            }
        });
    }

    [Fact]
    public async Task End_task_labels_distinguish_application_vs_process_pid_and_copy_commands_work()
    {
        var ui = new RecordingUi { ConfirmResult = true };
        var processes = new RecordingProcesses();
        var source = new ScriptedSource(new ConnectionSnapshot
        {
            CapturedUtc = DateTimeOffset.UtcNow,
            SourceName = "test",
            Connections =
            [
                Connection(@"C:\Apps\browser.exe", "browser.exe", 101, "10.0.0.2:5000", "93.184.216.34:443"),
                Connection(@"C:\Apps\browser.exe", "browser.exe", 202, "10.0.0.2:5001", "1.1.1.1:443"),
            ],
            ProcessCount = 2,
        });

        using var monitor = new ConnectionMonitor(source, new FakeTimerFactory());
        await monitor.PollAsync();

        using var apps = new AppsPageViewModel(monitor, null, ui, processes);
        var selectedApp = Assert.Single(apps.Apps);
        Assert.Equal("101, 202", selectedApp.PidText);

        apps.EndTaskAppCommand.Execute(selectedApp);
        Assert.Equal("End application", ui.LastConfirmTitle);
        Assert.Equal("End application", ui.LastConfirmLabel);
        Assert.Contains("101, 202", ui.LastConfirmBody, StringComparison.Ordinal);
        Assert.Equal([101, 202], processes.EndedPids);

        apps.CopyDetailsAppCommand.Execute(selectedApp);
        Assert.Contains("Application: browser.exe", ui.LastCopied, StringComparison.Ordinal);
        Assert.Contains("PIDs: 101, 202", ui.LastCopied, StringComparison.Ordinal);

        var appStatusBeforeCopy = apps.WriteStatusText;
        apps.CopyStatusCommand.Execute(null);
        Assert.Equal(appStatusBeforeCopy, ui.LastCopied);

        using var connections = new ConnectionsPageViewModel(monitor, ui, null, processes);
        connections.IsGroupedByApp = false;
        var row = connections.VisibleConnections[0];
        connections.EndTaskCommand.Execute(row);
        Assert.Equal("End process (PID)", ui.LastConfirmTitle);
        Assert.Equal("End process", ui.LastConfirmLabel);
        Assert.Equal([101], processes.EndedPids);

        var connStatusBeforeCopy = connections.StatusText;
        connections.CopyStatusCommand.Execute(null);
        Assert.Equal(connStatusBeforeCopy, ui.LastCopied);
    }

    [Fact]
    public async Task Dashboard_views_expose_scoped_end_labels_and_clickable_selectable_rows()
    {
        var source = new ScriptedSource(new ConnectionSnapshot
        {
            CapturedUtc = DateTimeOffset.UtcNow,
            SourceName = "test",
            Connections =
            [
                Connection(@"C:\Apps\alpha.exe", "alpha.exe", 111, "10.0.0.2:1001", "8.8.8.8:53"),
                Connection(@"C:\Apps\beta.exe", "beta.exe", 222, "10.0.0.2:1002", "1.1.1.1:443"),
            ],
            ProcessCount = 2,
        });
        using var monitor = new ConnectionMonitor(source, new FakeTimerFactory());
        await monitor.PollAsync();

        TestAppBuilder.RunOnUiThread(() =>
        {
            var ui = new RecordingUi();

            using var apps = new AppsPageViewModel(monitor, null, ui, new RecordingProcesses());
            var appsView = new AppsView { DataContext = apps };
            var appsWindow = new Window { Width = 1100, Height = 750, Content = appsView };
            appsWindow.Show();
            Dispatcher.UIThread.RunJobs();

            Assert.DoesNotContain(appsView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "End task"));
            Assert.Contains(appsView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "End application"));
            Assert.Contains(appsView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "Copy details"));
            Assert.Contains(appsView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "Copy status"));

            var appsList = appsView.GetVisualDescendants().OfType<ListBox>().First();
            var secondContainer = appsList.ContainerFromIndex(1);
            Assert.NotNull(secondContainer);
            var betaCell = secondContainer!
                .GetVisualDescendants()
                .OfType<AxiomSelectableTextBlock>()
                .FirstOrDefault(tb => string.Equals(tb.Text, "beta.exe", StringComparison.Ordinal));
            Assert.NotNull(betaCell);
            ClickControl(appsWindow, betaCell!, MouseButton.Left);
            Assert.Equal("beta.exe", apps.SelectedApp?.Name);
            appsWindow.Close();

            using var connections = new ConnectionsPageViewModel(monitor, ui, null, new RecordingProcesses());
            var connView = new ConnectionsView { DataContext = connections };
            var connWindow = new Window { Width = 1200, Height = 750, Content = connView };
            connWindow.Show();
            Dispatcher.UIThread.RunJobs();
            Assert.DoesNotContain(connView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "End task"));
            Assert.Contains(connView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "End process (PID)"));
            Assert.Contains(connView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "Copy row"));
            Assert.Contains(connView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "Copy local"));
            Assert.Contains(connView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "Copy status"));
            connWindow.Close();

            using var events = new EventsPageViewModel(null, new FakeTimerFactory(), ui);
            var eventsView = new EventsView { DataContext = events };
            var eventsWindow = new Window { Width = 1200, Height = 750, Content = eventsView };
            eventsWindow.Show();
            Dispatcher.UIThread.RunJobs();
            Assert.DoesNotContain(eventsView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "End task"));
            Assert.Contains(eventsView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "End process (PID)"));
            Assert.Contains(eventsView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "Copy remote"));
            Assert.Contains(eventsView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "Copy status"));
            eventsWindow.Close();

            using var traffic = new TrafficEngine(new FakeTimerFactory());
            using var overview = new OverviewPageViewModel(monitor, traffic, ui, null, new RecordingProcesses());
            var overviewView = new OverviewView { DataContext = overview };
            var overviewWindow = new Window { Width = 1200, Height = 900, Content = overviewView };
            overviewWindow.Show();
            Dispatcher.UIThread.RunJobs();
            Assert.DoesNotContain(overviewView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "End task"));
            Assert.Contains(overviewView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "End process (PID)"));
            Assert.Contains(overviewView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "Copy row"));
            Assert.Contains(overviewView.GetVisualDescendants().OfType<Button>(), b => Equals(b.Content, "Copy status"));
            overviewWindow.Close();
        });
    }

    private static void ClickControl(Window window, Control target, MouseButton button)
    {
        target.BringIntoView();
        Dispatcher.UIThread.RunJobs();
        var center = target.TranslatePoint(
            new Point(Math.Max(1, target.Bounds.Width / 2), Math.Max(1, target.Bounds.Height / 2)),
            window);
        Assert.NotNull(center);
        window.MouseDown(center!.Value, button);
        window.MouseUp(center.Value, button);
        Dispatcher.UIThread.RunJobs();
    }

    private static ConnectionSnapshot EmptySnapshot() => new()
    {
        CapturedUtc = DateTimeOffset.UtcNow,
        SourceName = "test",
        Connections = [],
        ProcessCount = 0,
    };

    private static LiveConnection Connection(string path, string name, int pid, string local, string remote) => new()
    {
        AppDisplayName = name,
        AppPath = path,
        ProcessId = pid,
        Protocol = TransportProtocol.Tcp,
        LocalEndpoint = local,
        RemoteEndpoint = remote,
        State = "Established",
        Direction = ConnectionDirection.Outbound,
        InterfaceName = string.Empty,
        FirstObservedUtc = DateTimeOffset.UnixEpoch,
        ObservedBytesSent = 1,
        ObservedBytesReceived = 1,
    };

    private sealed class ScriptedSource(ConnectionSnapshot snapshot) : IConnectionSnapshotSource
    {
        public string Name => "test";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(snapshot);
    }

    private sealed class RecordingUi : IUserInteraction
    {
        public bool ConfirmResult { get; set; }

        public string? LastConfirmTitle { get; private set; }

        public string? LastConfirmBody { get; private set; }

        public string? LastConfirmLabel { get; private set; }

        public string? LastCopied { get; private set; }

        public Task<bool> ConfirmAsync(
            string title,
            string message,
            string confirmLabel,
            bool destructive,
            CancellationToken cancellationToken)
        {
            LastConfirmTitle = title;
            LastConfirmBody = message;
            LastConfirmLabel = confirmLabel;
            return Task.FromResult(ConfirmResult);
        }

        public Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task ShowDocumentAsync(string title, string document, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<string?> PickSaveFileAsync(
            string suggestedFileName,
            string extension,
            string typeName,
            CancellationToken cancellationToken) => Task.FromResult<string?>(null);

        public Task<string?> PickOpenFileAsync(
            string title,
            string extension,
            string typeName,
            CancellationToken cancellationToken) => Task.FromResult<string?>(null);

        public Task<string?> PickFolderAsync(string title, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task CopyTextAsync(string text, CancellationToken cancellationToken)
        {
            LastCopied = text;
            return Task.CompletedTask;
        }

        public Task OpenExternalAsync(string url, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class RecordingProcesses : IProcessActions
    {
        public int[] EndedPids { get; private set; } = [];

        public int EndProcesses(IReadOnlyList<int> processIds)
        {
            EndedPids = [.. processIds];
            return processIds.Count;
        }
    }

    private sealed class FakeTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new FakeTimer();

        private sealed class FakeTimer : IUiTimer
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

            public void Dispose() => IsEnabled = false;
        }
    }
}
