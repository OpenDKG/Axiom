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
using Axiom.Contracts.Blackbox;
using Axiom.Contracts.History;
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;
using Axiom.UI.Avalonia.Views;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class AgentActivitySelectionTests
{
    [Fact]
    public void Clicking_and_right_clicking_row_cells_on_agent_dashboard_selects_the_row_and_updates_details()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var ui = new RecordingUserInteraction();
            using var shell = CreateShell(ui);
            var agents = shell.Agents;
            var entry1 = MakeEntry(1, "pre_tool_call", "read_file", "{\"id\":1}");
            var entry2 = MakeEntry(2, "pre_tool_call", "write_file", "{\"id\":2}");
            var finding1 = MakeFinding(1, "secret:api-key", "block");
            var finding2 = MakeFinding(2, "fileaccess:wallet", "flag");

            agents.ApplyActivity(new BlackboxAuditPage([entry1, entry2], 2));
            agents.ApplyFindings(new BlackboxFindingPage([finding1, finding2], 2));

            var window = new Window
            {
                Width = 1280,
                Height = 1100,
                Content = new AgentDashboardView { DataContext = shell.Pages[0] },
            };
            window.Show();
            Dispatcher.UIThread.RunJobs();

            var lists = window.GetVisualDescendants().OfType<ListBox>().ToList();
            var activityList = lists.First(list => ReferenceEquals(list.ItemsSource, agents.Activity));
            var findingsList = lists.First(list => ReferenceEquals(list.ItemsSource, agents.Findings));

            var firstActivityCell = GetRowCell(activityList, 0, "read_file");
            Assert.NotNull(firstActivityCell);
            ClickControl(window, firstActivityCell!, MouseButton.Left);
            Assert.Equal(entry1, agents.SelectedActivity);
            Assert.True(agents.HasSelectedActivity);

            var secondActivityCell = GetRowCell(activityList, 1, "write_file");
            Assert.NotNull(secondActivityCell);
            ClickControl(window, secondActivityCell!, MouseButton.Right);
            Assert.Equal(entry2, agents.SelectedActivity);
            Assert.Contains("write_file", agents.SelectedActivityDetails.Select(row => row.Value));

            // Findings are sorted newest-first, so finding2 ("fileaccess:wallet") is at index 0.
            var topFindingCell = GetRowCell(findingsList, 0, "fileaccess:wallet");
            Assert.NotNull(topFindingCell);
            ClickControl(window, topFindingCell!, MouseButton.Right);
            Assert.Equal(finding2, agents.SelectedFinding);
            Assert.True(agents.HasSelectedFinding);

            window.Close();
        });
    }

    [Fact]
    public void Clicking_row_cells_on_agent_stats_view_selects_activity_and_findings()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var ui = new RecordingUserInteraction();
            using var shell = CreateShell(ui);
            var agents = shell.Agents;
            var entry1 = MakeEntry(1, "pre_tool_call", "first_cmd", "{\"id\":11}");
            var entry2 = MakeEntry(2, "pre_tool_call", "second_cmd", "{\"id\":22}");
            var finding1 = MakeFinding(1, "secret:seed", "block");

            agents.ApplyActivity(new BlackboxAuditPage([entry1, entry2], 2));
            agents.ApplyFindings(new BlackboxFindingPage([finding1], 1));

            var window = new Window
            {
                Width = 1280,
                Height = 1400,
                Content = new AgentStatsView { DataContext = agents },
            };
            window.Show();
            Dispatcher.UIThread.RunJobs();

            var lists = window.GetVisualDescendants().OfType<ListBox>().ToList();
            var activityList = lists.First(list => ReferenceEquals(list.ItemsSource, agents.Activity));
            var findingsList = lists.First(list => ReferenceEquals(list.ItemsSource, agents.Findings));

            var secondCell = GetRowCell(activityList, 1, "second_cmd");
            Assert.NotNull(secondCell);
            ClickControl(window, secondCell!, MouseButton.Left);
            Assert.Equal(entry2, agents.SelectedActivity);

            var findingCell = GetRowCell(findingsList, 0, finding1.Title);
            Assert.NotNull(findingCell);
            ClickControl(window, findingCell!, MouseButton.Right);
            Assert.Equal(finding1, agents.SelectedFinding);

            window.Close();
        });
    }

    [Fact]
    public void Copy_commands_act_on_the_context_menu_row_and_periodic_refresh_keeps_selection()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var ui = new RecordingUserInteraction();
            using var shell = CreateShell(ui);
            var agents = shell.Agents;

            var entry1 = MakeEntry(1, "pre_tool_call", "cmd_alpha", "{\"seq\":1}");
            var entry2 = MakeEntry(2, "pre_tool_call", "cmd_beta", "{\"seq\":2}");
            var entry3 = MakeEntry(3, "pre_tool_call", "cmd_gamma", "{\"seq\":3}");
            var finding1 = MakeFinding(1, "id-1", "block");
            var finding2 = MakeFinding(2, "id-2", "flag");

            agents.ApplyActivity(new BlackboxAuditPage([entry2, entry1], 2));
            agents.ApplyFindings(new BlackboxFindingPage([finding2, finding1], 2));

            // Copy commands invoked with an explicit row (the ContextMenu target) act on that row.
            agents.CopyActivityEventCommand.Execute(entry1);
            Dispatcher.UIThread.RunJobs();
            Assert.Equal(entry1, agents.SelectedActivity);
            Assert.Contains("cmd_alpha", ui.LastClipboardText);

            agents.CopyActivityJsonCommand.Execute(entry2);
            Dispatcher.UIThread.RunJobs();
            Assert.Equal(entry2, agents.SelectedActivity);
            Assert.Equal("{\"seq\":2}", ui.LastClipboardText);

            agents.CopyFindingCommand.Execute(finding1);
            Dispatcher.UIThread.RunJobs();
            Assert.Equal(finding1, agents.SelectedFinding);
            Assert.Contains("id-1", ui.LastClipboardText);

            // Periodic merge refresh prepends entry3 and adds a new finding while keeping selection.
            agents.MergeActivity(new BlackboxAuditPage([entry3, entry2, entry1], 3));
            var finding3 = MakeFinding(3, "id-3", "block");
            agents.ApplyFindings(new BlackboxFindingPage([finding3, finding2, finding1], 3));

            Assert.Equal(entry2, agents.SelectedActivity);
            Assert.True(agents.HasSelectedActivity);
            Assert.Equal(finding1, agents.SelectedFinding);
            Assert.True(agents.HasSelectedFinding);
        });
    }

    [Fact]
    public void Clicking_row_padding_edge_selects_and_container_survives_refresh()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var ui = new RecordingUserInteraction();
            using var shell = CreateShell(ui);
            var agents = shell.Agents;
            var entry1 = MakeEntry(1, "pre_tool_call", "edge_alpha", "{\"id\":101}");
            var entry2 = MakeEntry(2, "pre_tool_call", "edge_beta", "{\"id\":102}");
            var finding1 = MakeFinding(1, "secret:edge-1", "block");
            var finding2 = MakeFinding(2, "secret:edge-2", "flag");

            agents.ApplyActivity(new BlackboxAuditPage([entry2, entry1], 2));
            agents.ApplyFindings(new BlackboxFindingPage([finding2, finding1], 2));

            var window = new Window
            {
                Width = 1280,
                Height = 1100,
                Content = new AgentDashboardView { DataContext = shell.Pages[0] },
            };
            window.Show();
            Dispatcher.UIThread.RunJobs();

            var lists = window.GetVisualDescendants().OfType<ListBox>().ToList();
            var activityList = lists.First(list => ReferenceEquals(list.ItemsSource, agents.Activity));
            var findingsList = lists.First(list => ReferenceEquals(list.ItemsSource, agents.Findings));

            var activityItem = Assert.IsType<ListBoxItem>(activityList.ContainerFromIndex(1));
            ClickEdge(window, activityItem, MouseButton.Left);
            Assert.Equal(entry1, agents.SelectedActivity);
            Assert.True(agents.HasSelectedActivity);

            var findingItem = Assert.IsType<ListBoxItem>(findingsList.ContainerFromIndex(1));
            ClickEdge(window, findingItem, MouseButton.Left);
            Assert.Equal(finding1, agents.SelectedFinding);
            Assert.True(agents.HasSelectedFinding);

            var entry3 = MakeEntry(3, "pre_tool_call", "edge_gamma", "{\"id\":103}");
            var finding3 = MakeFinding(3, "secret:edge-3", "block");
            agents.MergeActivity(new BlackboxAuditPage([entry3, entry2, entry1], 3));
            agents.ApplyFindings(new BlackboxFindingPage([finding3, finding2, finding1], 3));
            Dispatcher.UIThread.RunJobs();

            Assert.Equal(entry1, agents.SelectedActivity);
            Assert.True(agents.HasSelectedActivity);
            Assert.Equal(finding1, agents.SelectedFinding);
            Assert.True(agents.HasSelectedFinding);
            Assert.Same(activityItem, activityList.ContainerFromIndex(2));
            Assert.Same(findingItem, findingsList.ContainerFromIndex(2));

            window.Close();
        });
    }

    [Fact]
    public void Clicking_rows_across_connections_apps_overview_and_events_selects_items()
    {
        var conn1 = MakeConnection("alpha.exe", @"C:\Apps\alpha.exe", 101, "93.184.216.34:443");
        var conn2 = MakeConnection("beta.exe", @"C:\Apps\beta.exe", 202, "1.1.1.1:443");
        var source = new StaticSource([conn1, conn2]);

        TestAppBuilder.RunOnUiThread(() =>
        {
            var ui = new RecordingUserInteraction();
            var timers = new FakeTimerFactory();
            using var shell = new ShellViewModel(source, timers, userInteraction: ui);
            shell.Connections.Activate();
            shell.Overview.Activate();
            shell.Apps.Activate();

            // Trigger an immediate synchronous poll through ShellViewModel so Overview, Apps, and
            // Connections all populate their view-model lists.
            shell.Start();
            Dispatcher.UIThread.RunJobs();

            shell.Connections.IsGroupedByApp = true;
            foreach (var group in shell.Connections.Groups)
            {
                group.IsExpanded = true;
            }

            var connWindow = new Window
            {
                Width = 1280,
                Height = 900,
                Content = new ConnectionsView { DataContext = shell.Connections },
            };
            connWindow.Show();
            Dispatcher.UIThread.RunJobs();

            var groupLists = connWindow.GetVisualDescendants()
                .OfType<ListBox>()
                .Where(list => list.Items.Count > 0 && !ReferenceEquals(list.ItemsSource, shell.Connections.VisibleConnections))
                .ToList();
            Assert.Equal(2, groupLists.Count);

            var secondGroupRow = GetRowCell(groupLists[1], 0, "1.1.1.1:443");
            Assert.NotNull(secondGroupRow);
            ClickControl(connWindow, secondGroupRow!, MouseButton.Left);
            Assert.NotNull(shell.Connections.SelectedConnection);
            Assert.Equal("beta.exe", shell.Connections.SelectedConnection!.AppDisplayName);

            var firstGroupItem = Assert.IsType<ListBoxItem>(groupLists[0].ContainerFromIndex(0));
            ClickEdge(connWindow, firstGroupItem, MouseButton.Left);
            Assert.NotNull(shell.Connections.SelectedConnection);
            Assert.Equal("alpha.exe", shell.Connections.SelectedConnection!.AppDisplayName);

            shell.Connections.IsGroupedByApp = false;
            Dispatcher.UIThread.RunJobs();
            var flatList = connWindow.GetVisualDescendants()
                .OfType<ListBox>()
                .First(list => ReferenceEquals(list.ItemsSource, shell.Connections.VisibleConnections));
            var flatRow = GetRowCell(flatList, 1, "beta.exe");
            Assert.NotNull(flatRow);
            ClickControl(connWindow, flatRow!, MouseButton.Left);
            Assert.Equal("beta.exe", shell.Connections.SelectedConnection!.AppDisplayName);
            connWindow.Close();

            var appsWindow = new Window
            {
                Width = 1280,
                Height = 900,
                Content = new AppsView { DataContext = shell.Apps },
            };
            appsWindow.Show();
            Dispatcher.UIThread.RunJobs();
            var appsList = appsWindow.GetVisualDescendants().OfType<ListBox>().First();
            var betaCell = GetRowCell(appsList, 1, "beta.exe");
            Assert.NotNull(betaCell);
            ClickControl(appsWindow, betaCell!, MouseButton.Left);
            Assert.Equal("beta.exe", shell.Apps.SelectedApp?.Name);
            appsWindow.Close();

            if (shell.Overview.NewConnectionEvents.Count < 2)
            {
                shell.Overview.NewConnectionEvents.Clear();
                shell.Overview.NewConnectionEvents.Add(new NewConnectionMarkerEvent(
                    1, DateTimeOffset.UtcNow.AddSeconds(-5), "alpha.exe", "93.184.216.34:443", "Outbound", "Established", 101, @"C:\Apps\alpha.exe", "TCP", "127.0.0.1:50000"));
                shell.Overview.NewConnectionEvents.Add(new NewConnectionMarkerEvent(
                    2, DateTimeOffset.UtcNow, "beta.exe", "1.1.1.1:443", "Outbound", "Established", 202, @"C:\Apps\beta.exe", "TCP", "127.0.0.1:50001"));
            }

            var overviewWindow = new Window
            {
                Width = 1280,
                Height = 1400,
                Content = new OverviewView { DataContext = shell.Overview },
            };
            overviewWindow.Show();
            Dispatcher.UIThread.RunJobs();
            var overviewLists = overviewWindow.GetVisualDescendants().OfType<ListBox>().ToList();
            var markersList = overviewLists.First(list => ReferenceEquals(list.ItemsSource, shell.Overview.NewConnectionEvents));
            var socketsList = overviewLists.First(list => ReferenceEquals(list.ItemsSource, shell.Overview.Connections));
            var markerItem = Assert.IsType<ListBoxItem>(markersList.ContainerFromIndex(1));
            ClickEdge(overviewWindow, markerItem, MouseButton.Left);
            Assert.NotNull(shell.Overview.SelectedEvent);
            Assert.Equal("beta.exe", shell.Overview.SelectedEvent!.App);
            var socketCell = GetRowCell(socketsList, 1, "beta.exe");
            Assert.NotNull(socketCell);
            ClickControl(overviewWindow, socketCell!, MouseButton.Left);
            Assert.Equal("beta.exe", shell.Overview.SelectedSocket?.AppDisplayName);
            overviewWindow.Close();

            // Also verify grouped EventsView selection via SharedSelectedItem across multiple app groups.
            shell.Events.IsGroupedByApp = true;
            var evt1 = new EventRowView(new HistoryRow
            {
                AppDisplayName = "alpha.exe",
                AppPath = @"C:\Apps\alpha.exe",
                ProcessId = 101,
                Protocol = "TCP",
                LocalEndpoint = "127.0.0.1:5000",
                RemoteEndpoint = "93.184.216.34:443",
                Direction = "Outbound",
                State = "Established",
                Quality = "Live",
                FirstSeenUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
                LastSeenUtc = DateTimeOffset.UtcNow,
            });
            var evt2 = new EventRowView(new HistoryRow
            {
                AppDisplayName = "beta.exe",
                AppPath = @"C:\Apps\beta.exe",
                ProcessId = 202,
                Protocol = "TCP",
                LocalEndpoint = "127.0.0.1:5001",
                RemoteEndpoint = "1.1.1.1:443",
                Direction = "Outbound",
                State = "Established",
                Quality = "Live",
                FirstSeenUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
                LastSeenUtc = DateTimeOffset.UtcNow,
            });
            var grp1 = new EventAppGroup("alpha") { IsExpanded = true };
            grp1.Update("alpha.exe", @"C:\Apps\alpha.exe", [evt1]);
            var grp2 = new EventAppGroup("beta") { IsExpanded = true };
            grp2.Update("beta.exe", @"C:\Apps\beta.exe", [evt2]);
            shell.Events.AppGroups.Add(grp1);
            shell.Events.AppGroups.Add(grp2);
            shell.Events.IsEmpty = false;

            var eventsWindow = new Window
            {
                Width = 1280,
                Height = 900,
                Content = new EventsView { DataContext = shell.Events },
            };
            eventsWindow.Show();
            Dispatcher.UIThread.RunJobs();
            var eventGroupLists = eventsWindow.GetVisualDescendants()
                .OfType<ListBox>()
                .Where(list => list.Items.Count > 0 && !ReferenceEquals(list.ItemsSource, shell.Events.Rows))
                .ToList();
            Assert.Equal(2, eventGroupLists.Count);
            var evtCell2 = GetRowCell(eventGroupLists[1], 0, "1.1.1.1:443");
            Assert.NotNull(evtCell2);
            ClickControl(eventsWindow, evtCell2!, MouseButton.Left);
            Assert.Equal(evt2, shell.Events.SelectedEvent);
            var evtCell1 = GetRowCell(eventGroupLists[0], 0, "93.184.216.34:443");
            Assert.NotNull(evtCell1);
            ClickEdge(eventsWindow, Assert.IsType<ListBoxItem>(eventGroupLists[0].ContainerFromIndex(0)), MouseButton.Left);
            Assert.Equal(evt1, shell.Events.SelectedEvent);
            eventsWindow.Close();
        });
    }

    private static void ClickEdge(Window window, Control target, MouseButton button)
    {
        target.BringIntoView();
        Dispatcher.UIThread.RunJobs();
        var edge = target.TranslatePoint(new Point(2, 2), window);
        Assert.NotNull(edge);
        window.MouseDown(edge!.Value, button);
        window.MouseUp(edge.Value, button);
        Dispatcher.UIThread.RunJobs();
    }

    private static LiveConnection MakeConnection(string name, string path, int pid, string remote) =>
        new()
        {
            AppDisplayName = name,
            AppPath = path,
            ProcessId = pid,
            Protocol = TransportProtocol.Tcp,
            LocalEndpoint = "127.0.0.1:50000",
            RemoteEndpoint = remote,
            State = "Established",
            Direction = ConnectionDirection.Outbound,
            InterfaceName = "eth0",
            FirstObservedUtc = DateTimeOffset.UtcNow,
        };

    private sealed class StaticSource(IReadOnlyList<LiveConnection> connections) : IConnectionSnapshotSource
    {
        public string Name => "test-static";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UtcNow,
                Connections = connections,
                ProcessCount = connections.Count,
                SourceName = Name,
            });
    }

    private static TextBlock? GetRowCell(ListBox listBox, int index, string text)
    {
        var container = listBox.ContainerFromIndex(index);
        if (container is null)
        {
            return null;
        }

        return container
            .GetVisualDescendants()
            .OfType<TextBlock>()
            .FirstOrDefault(tb => string.Equals(tb.Text, text, StringComparison.Ordinal));
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

    private static BlackboxAuditEntry MakeEntry(int minuteOffset, string ev, string action, string rawJson) =>
        new(
            Timestamp: new DateTimeOffset(2026, 11, 14, 12, minuteOffset, 0, TimeSpan.Zero),
            Event: ev,
            Agent: "codex",
            Session: "sess-1",
            Tool: "shell",
            Action: action,
            Decision: "allow",
            Severity: "low",
            Identifier: "id",
            Details: action)
        {
            RawJson = rawJson,
            Detail = new BlackboxActivityDetail(
                "sess-1", "tc-1", "", "C:\\repo", "", "", action, "", "", "", "", "", "", "", "", "", null,
                "", "", "", "", "", false),
        };

    private static BlackboxFinding MakeFinding(int minuteOffset, string identifier, string decision) =>
        new(
            Timestamp: new DateTimeOffset(2026, 11, 14, 12, minuteOffset, 0, TimeSpan.Zero),
            Identifier: identifier,
            Category: "secret",
            Severity: "high",
            Title: $"Finding {identifier}",
            Agent: "codex",
            Session: "sess-1",
            Tool: "read_file",
            Decision: decision,
            Source: "guard",
            Confirmed: true);

    private static ShellViewModel CreateShell(RecordingUserInteraction ui) =>
        new(new FakeSource(), new FakeTimerFactory(), userInteraction: ui);

    private sealed class RecordingUserInteraction : IUserInteraction
    {
        public string LastClipboardText { get; private set; } = string.Empty;

        public Task<bool> ConfirmAsync(string title, string message, string confirmLabel, bool destructive, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task ShowDocumentAsync(string title, string document, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<string?> PickSaveFileAsync(string suggestedFileName, string extension, string typeName, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task<string?> PickOpenFileAsync(string title, string extension, string typeName, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task<string?> PickFolderAsync(string title, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task CopyTextAsync(string text, CancellationToken cancellationToken)
        {
            LastClipboardText = text;
            return Task.CompletedTask;
        }

        public Task OpenExternalAsync(string url, CancellationToken cancellationToken) =>
            Task.CompletedTask;
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
