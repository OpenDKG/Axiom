// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Avalonia.Threading;
using Axiom.Contracts.Blackbox;
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

[CollectionDefinition("AlertCenterSerial", DisableParallelization = true)]
public sealed class AlertCenterSerialDefinition;

[Collection("AlertCenterSerial")]
public sealed class UiFixesRegressionTests
{
    [Fact]
    public void Selecting_hook_evidence_populates_right_side_details_with_correlated_blocked_info()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var timers = new FakeTimerFactory();
            using var security = new SecurityPageViewModel(
                new FakeUi(),
                new UnsupportedSecurityDialogs(),
                new UnsupportedApiKeyProtector(),
                timers,
                new UnsupportedShellActions());
            using var agents = new AgentsPageViewModel(
                security,
                agentSessions: null,
                new FakeUi(),
                new UnsupportedBlackboxDialogs(),
                timers);

            var utc = new DateTimeOffset(2026, 11, 21, 19, 30, 15, TimeSpan.Zero);
            agents.ApplyActivity(new BlackboxAuditPage(
            [
                new BlackboxAuditEntry(
                    utc,
                    "blocked",
                    "openchamber",
                    "sess-42",
                    "shell",
                    "Read protected key C:\\Users\\llm\\.axiom-probe\\canary.key",
                    "block",
                    "critical",
                    "secret:private-key",
                    "Blocked by Blackbox guard")
                {
                    Detail = new BlackboxActivityDetail(
                        SessionId: "sess-42",
                        ToolCallId: "call-42",
                        TaskId: string.Empty,
                        Workspace: @"D:\repo",
                        Model: string.Empty,
                        Provider: string.Empty,
                        Command: "type C:\\Users\\llm\\.axiom-probe\\canary.key",
                        Path: @"C:\Users\llm\.axiom-probe\canary.key",
                        Mode: "block",
                        Url: string.Empty,
                        Query: string.Empty,
                        Ecosystem: string.Empty,
                        Package: string.Empty,
                        Version: string.Empty,
                        ResultStatus: "blocked",
                        ResultText: string.Empty,
                        DurationMs: 12,
                        FindingTitle: "Protected key file access",
                        FindingIdentifier: "secret:private-key",
                        FindingCategory: "fileaccess",
                        FindingEvidence: string.Empty,
                        FindingSource: "blackbox",
                        Confirmed: true),
                },
            ],
            Total: 1));
            agents.ApplyFindings(new BlackboxFindingPage(
            [
                new BlackboxFinding(
                    utc,
                    "secret:private-key",
                    "fileaccess",
                    "critical",
                    "Protected key file access",
                    "openchamber",
                    "sess-42",
                    "shell",
                    "block",
                    "blackbox",
                    Confirmed: true),
            ],
            Total: 1));

            var evidence = new AgentEvidenceEvent(
                utc,
                "opencode",
                "GUARD_BLOCKED",
                "shell",
                "block",
                "blocked",
                12,
                string.Empty)
            {
                Session = "sess-42",
                Call = "call-42",
                Channel = "HOST_DENY_SENT",
            };

            agents.SelectedHookEvidence = evidence;

            Assert.True(agents.HasSelectedHookEvidence);
            Assert.True(agents.IsSelectedHookEvidenceBlocked);
            Assert.False(agents.IsSelectedHookEvidenceAllowed);
            Assert.Contains("BLOCKED", agents.SelectedHookEvidenceTitle, StringComparison.Ordinal);
            Assert.Contains(agents.SelectedHookEvidenceDetails, row =>
                row.Label == "Date & time" &&
                row.Value == utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
            Assert.Contains(agents.SelectedHookEvidenceDetails, row =>
                row.Label == "Blocked / finding" &&
                row.Value == "Protected key file access");
            Assert.Contains(agents.SelectedHookEvidenceDetails, row =>
                row.Label == "Identifier" &&
                row.Value == "secret:private-key");
            Assert.Contains(agents.SelectedHookEvidenceDetails, row =>
                row.Label == "Command" &&
                row.Value.Contains("canary.key", StringComparison.Ordinal));
        });
    }

    [Fact]
    public void Disabling_notifications_suppresses_non_forced_alerts_and_unread_badge()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var previous = NotificationSettingsStore.Enabled;
            AlertCenter.Clear();
            try
            {
                NotificationSettingsStore.SetEnabled(false);

                AxiomAlertService.Show("Blocked action", "Suppressed when off", force: false);
                Dispatcher.UIThread.RunJobs();
                Assert.Empty(AlertCenter.Items);
                Assert.Equal(0, AlertCenter.UnreadCount);

                AxiomAlertService.Show("Preview alert", "Allowed when forced", force: true);
                Dispatcher.UIThread.RunJobs();
                Assert.Single(AlertCenter.Items);
                Assert.Equal(1, AlertCenter.UnreadCount);
            }
            finally
            {
                AlertCenter.Clear();
                NotificationSettingsStore.SetEnabled(previous);
            }
        });
    }

    [Fact]
    public void Connected_and_not_connected_status_helpers_map_cleanly()
    {
        var connected = new SecurityModule("Blackbox", "CONNECTED", "Running", "\uE7BA", IsConnected: true);
        var checking = new SecurityModule("Blackbox", "CHECKING", "Checking", "\uE7BA", IsConnected: false);
        var disconnected = new SecurityModule("Blackbox", "NOT CONNECTED", "Offline", "\uE7BA", IsConnected: false);
        var notRunning = new SecurityModule("OriginTrail DKG", "NOT RUNNING", "Stopped", "\uE968", IsConnected: false);

        Assert.False(connected.IsDisconnected);
        Assert.True(checking.IsChecking);
        Assert.False(checking.IsDisconnected);
        Assert.True(disconnected.IsDisconnected);
        Assert.True(notRunning.IsDisconnected);

        var agentDisconnected = new ProtectedAgent("opencode", "C:\\ws", "NOT CONNECTED", "Offline");
        var agentConnected = new ProtectedAgent("opencode", "C:\\ws", "HOOK LOADED", "Loaded");
        Assert.True(agentDisconnected.ToneFail);
        Assert.False(agentDisconnected.ToneOk);
        Assert.True(agentConnected.ToneOk);
        Assert.False(agentConnected.ToneFail);

        using var monitor = new ConnectionMonitor(new EmptySnapshotSource(), new FakeTimerFactory());
        using var settingsConnected = new SettingsPageViewModel(
            monitor,
            serviceMode: true,
            new FixedThemeService(),
            new UnsupportedAutostartService());
        using var settingsDisconnected = new SettingsPageViewModel(
            monitor,
            serviceMode: false,
            new FixedThemeService(),
            new UnsupportedAutostartService());
        Assert.True(settingsConnected.IsServiceConnected);
        Assert.False(settingsDisconnected.IsServiceConnected);
    }

    [Fact]
    public void Bundled_privacy_policy_covers_eu_switzerland_us_and_blackbox_sharing()
    {
        var policy = AxiomDocuments.PrivacyPolicy;

        Assert.DoesNotContain("is missing from this build", policy, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("GDPR", policy, StringComparison.Ordinal);
        Assert.Contains("Switzerland", policy, StringComparison.Ordinal);
        Assert.Contains("revFADP", policy, StringComparison.Ordinal);
        Assert.Contains("United States", policy, StringComparison.Ordinal);
        Assert.Contains("Blackbox", policy, StringComparison.Ordinal);
        Assert.Contains("contact@opendkg.org", policy, StringComparison.Ordinal);
    }

    private sealed class EmptySnapshotSource : IConnectionSnapshotSource
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

    private sealed class FakeUi : IUserInteraction
    {
        public Task<bool> ConfirmAsync(string title, string message, string confirmLabel, bool destructive, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task ShowDocumentAsync(string title, string documentText, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string?> PickSaveFileAsync(string suggestedFileName, string extension, string typeName, CancellationToken cancellationToken) => Task.FromResult<string?>(null);
        public Task<string?> PickOpenFileAsync(string title, string extension, string typeName, CancellationToken cancellationToken) => Task.FromResult<string?>(null);
        public Task<string?> PickFolderAsync(string title, CancellationToken cancellationToken) => Task.FromResult<string?>(null);
        public Task CopyTextAsync(string text, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task OpenExternalAsync(string url, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class FakeTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new FakeTimer(interval);

        private sealed class FakeTimer(TimeSpan interval) : IUiTimer
        {
            public TimeSpan Interval { get; set; } = interval;
            public bool IsEnabled { get; private set; }
            public event EventHandler? Tick { add { } remove { } }
            public void Start() => IsEnabled = true;
            public void StopTimer() => IsEnabled = false;
            public void Dispose() { }
        }
    }
}
