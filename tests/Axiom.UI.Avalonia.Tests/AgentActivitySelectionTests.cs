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
