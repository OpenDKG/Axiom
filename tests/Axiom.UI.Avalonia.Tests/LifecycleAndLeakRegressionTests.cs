// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Threading;
using Axiom.Contracts.Blackbox;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Contracts.Protection;
using Axiom.Presentation;
using Axiom.UI.Avalonia.Controls;
using Axiom.UI.Avalonia.Views;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

[Collection("AlertCenterSerial")]
public sealed class LifecycleAndLeakRegressionTests
{
    [Fact]
    public void Shell_enables_agent_tray_monitoring_on_mini_home_and_agent_health_pages()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var timers = new FakeTimerFactory();
            using var shell = new ShellViewModel(
                new FakeSnapshotSource(),
                timers,
                uiModeService: new FixedUiModeService(UiMode.Mini));
            shell.Start();

            // MiniHome is active initially in Mini mode.
            Assert.Same(shell.MiniHome, shell.SelectedPage);
            var agentTimer = FindAgentTimer(timers);
            Assert.NotNull(agentTimer);
            Assert.False(GetTrayMonitoring(shell.Agents));

            shell.SetPresentationVisible(false);
            Assert.True(GetTrayMonitoring(shell.Agents));
            Assert.True(agentTimer.IsEnabled);

            // Switch to Advanced -> AgentHealth and hide window to tray.
            shell.SetPresentationVisible(true);
            Assert.False(GetTrayMonitoring(shell.Agents));
            shell.SwitchToAdvancedModeCommand.Execute(null);
            shell.SelectedPage = shell.AgentHealth;
            shell.SetPresentationVisible(false);
            Assert.True(GetTrayMonitoring(shell.Agents));
            Assert.True(agentTimer.IsEnabled);

            // On Support (non-agent page), tray monitoring turns off.
            shell.SetPresentationVisible(true);
            shell.SelectedPage = shell.Support;
            shell.SetPresentationVisible(false);
            Assert.False(GetTrayMonitoring(shell.Agents));
            if (!shell.Agents.IsAutoSyncEnabled)
            {
                Assert.False(agentTimer.IsEnabled);
            }
        });
    }

    [Fact]
    public void Mini_home_activate_uses_summary_mode_without_activating_connections_tab()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var source = new CountingSnapshotSource();
            var timers = new FakeTimerFactory();
            using var shell = new ShellViewModel(
                source,
                timers,
                uiModeService: new FixedUiModeService(UiMode.Mini));
            shell.Start();

            var connectionsTab = shell.Connections;
            var initialCount = connectionsTab.VisibleConnections.Count;

            // Emit a new snapshot while MiniHome is active. Because MiniHome uses ActivateSummary,
            // ConnectionsTab remains deactivated and marks itself dirty rather than rebuilding on every tick.
            source.NextSnapshot = new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UtcNow,
                SourceName = "counting",
                ProcessCount = 1,
                Connections =
                [
                    new LiveConnection
                    {
                        Protocol = TransportProtocol.Tcp,
                        LocalEndpoint = "127.0.0.1:50000",
                        RemoteEndpoint = "93.184.216.34:443",
                        State = "ESTABLISHED",
                        ProcessId = 4242,
                        AppDisplayName = "probe.exe",
                        AppPath = @"C:\Apps\probe.exe",
                        Direction = ConnectionDirection.Outbound,
                        InterfaceName = string.Empty,
                        FirstObservedUtc = DateTimeOffset.UtcNow,
                    },
                ],
            };

            timers.Created[0].FireTick();
            Assert.Equal(initialCount, connectionsTab.VisibleConnections.Count);

            // Navigating to Connections activates it and flushes the dirty snapshot.
            connectionsTab.Activate();
            Assert.Single(connectionsTab.VisibleConnections);
        });
    }

    [Fact]
    public void Shell_dispose_during_or_before_update_and_service_probes_does_not_throw_ObjectDisposedException()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var timers = new FakeTimerFactory();
            var serviceClient = new HangingServiceClient();
            var probe = new ServiceStatusProbe(serviceClient);
            var shell = new ShellViewModel(
                new FakeSnapshotSource(),
                timers,
                serviceProbe: probe,
                serviceClient: serviceClient);
            shell.Start();

            var monitorTimer = timers.Created[0];
            var updateTimer = timers.Created[^1];

            // Dispose immediately while probes are in flight, then poke update/monitor entry points.
            shell.Dispose();

            var checkTask = shell.CheckForUpdatesAsync();
            Assert.True(checkTask.IsCompletedSuccessfully);
            Assert.False(checkTask.Result);

            monitorTimer.FireTick();
            updateTimer.FireTick();
            Dispatcher.UIThread.RunJobs();
        });
    }

    [Fact]
    public void Notify_new_pending_apps_resets_when_pending_list_empties()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            AlertCenter.Clear();
            var timers = new FakeTimerFactory();
            var client = new ScriptedProtectionClient();
            using var shell = new ShellViewModel(
                new FakeSnapshotSource(),
                timers,
                serviceProbe: new ServiceStatusProbe(client),
                serviceClient: client);
            shell.Start();

            var app = new ProtectionPendingApp
            {
                AppPath = @"C:\Apps\test-agent.exe",
                AppName = "test-agent",
                SocketCount = 1,
                FirstObservedUtc = DateTimeOffset.UtcNow,
                IsConnected = true,
            };

            // 1. First pending observation raises an alert.
            client.Pending = [app];
            AdvanceLastProtectionProbe(shell);
            TriggerProtectionProbe(shell, timers);
            Dispatcher.UIThread.RunJobs();
            Assert.Single(AlertCenter.Items, static alert => alert.ActionText == "Open Firewall");

            // 2. Pending list empties (user allowed/dismissed).
            client.Pending = [];
            AdvanceLastProtectionProbe(shell);
            TriggerProtectionProbe(shell, timers);
            Dispatcher.UIThread.RunJobs();
            Assert.Single(AlertCenter.Items, static alert => alert.ActionText == "Open Firewall");

            // 3. Same app becomes pending again later -> must alert again!
            client.Pending = [app];
            AdvanceLastProtectionProbe(shell);
            TriggerProtectionProbe(shell, timers);
            Dispatcher.UIThread.RunJobs();
            Assert.Equal(2, AlertCenter.Items.Count(static alert => alert.ActionText == "Open Firewall"));
            AlertCenter.Clear();
        });
    }

    [Fact]
    public void Agents_merge_activity_caps_retained_entries_at_activity_max()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var timers = new FakeTimerFactory();
            using var security = CreateSecurity(timers);
            using var agents = new AgentsPageViewModel(
                security,
                null,
                new FakeUi(),
                new FakeBlackboxDialogs(),
                timers);

            var initial = Enumerable.Range(0, 19_990)
                .Select(i => MakeEntry(i))
                .ToList();
            agents.ApplyActivity(new BlackboxAuditPage(initial, initial.Count));
            Assert.Equal(19_990, agents.Activity.Count);

            var added = Enumerable.Range(19_990, 50)
                .Select(i => MakeEntry(i))
                .ToList();
            agents.MergeActivity(new BlackboxAuditPage(added, 20_040));

            Assert.Equal(20_000, agents.Activity.Count);
        });
    }

    [Fact]
    public void Agents_and_ai_analyst_dispose_safely_without_unobserved_exceptions()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var timers = new FakeTimerFactory();
            using var monitor = new ConnectionMonitor(new FakeSnapshotSource(), timers);
            using var security = CreateSecurity(timers);
            var agents = new AgentsPageViewModel(
                security,
                null,
                new FakeUi(),
                new FakeBlackboxDialogs(),
                timers);
            agents.Activate();
            agents.Dispose();

            // Timer ticks after Dispose must no-op cleanly.
            foreach (var timer in timers.Created)
            {
                timer.FireTick();
            }

            var analyst = new AiAnalystPageViewModel(
                monitor,
                new FakeProtector(),
                timers,
                new FakeUi());
            analyst.AutomaticAnalysis = true;
            analyst.Enabled = true;
            analyst.Dispose();
            foreach (var timer in timers.Created)
            {
                timer.FireTick();
            }

            Dispatcher.UIThread.RunJobs();
        });
    }

    [Fact]
    public async Task Privacy_shield_cancel_uac_does_not_leave_auto_point_adapter_dns_enabled()
    {
        TestAppBuilder.StartUiThread();
        await Dispatcher.UIThread.InvokeAsync(async () =>
        {
            var timers = new FakeTimerFactory();
            var ui = new FakeUi { ConfirmResult = false };
            using var privacy = new PrivacyShieldPageViewModel(
                null,
                ui,
                new FakeDnsHelper(),
                timers);

            privacy.SelectedAdapter = new PrivacyShieldAdapterOption("Ethernet", "Test NIC", "1.1.1.1", true);
            typeof(PrivacyShieldPageViewModel)
                .GetField("_resolverActive", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(privacy, true);
            Assert.False(privacy.AutoPointAdapterDns);

            await privacy.EnableSystemDnsCommand.ExecuteAsync(null);

            Assert.False(privacy.AutoPointAdapterDns);
            Assert.Equal("Adapter DNS change cancelled.", privacy.DnsHelperStatusText);
        });
    }

    [Fact]
    public void Detached_views_and_traffic_chart_unsubscribe_and_firewall_view_reattaches_cleanly()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var timers = new FakeTimerFactory();
            using var shell = new ShellViewModel(new FakeSnapshotSource(), timers);

            var window = new Window { Width = 900, Height = 600 };
            window.Show();

            // 1. TrafficChartControl
            var upload = new ObservableCollection<double> { 1.0, 2.0 };
            var download = new ObservableCollection<double> { 3.0, 4.0 };
            var chart = new TrafficChartControl
            {
                UploadSeries = upload,
                DownloadSeries = download,
            };
            window.Content = chart;
            Dispatcher.UIThread.RunJobs();
            Assert.Equal(1, SubscriberCount(upload));
            Assert.Equal(1, SubscriberCount(download));

            window.Content = null;
            Dispatcher.UIThread.RunJobs();
            Assert.Equal(0, SubscriberCount(upload));
            Assert.Equal(0, SubscriberCount(download));

            // 2. PrivacyShieldView code-behind subscription attaches and detaches with visual tree
            var privacyView = new PrivacyShieldView { DataContext = shell.PrivacyShield };
            window.Content = privacyView;
            Dispatcher.UIThread.RunJobs();
            Assert.True(HasCollectionChangedTarget(shell.PrivacyShield.BlockedHistoryGroups, privacyView));

            window.Content = null;
            Dispatcher.UIThread.RunJobs();
            Assert.False(HasCollectionChangedTarget(shell.PrivacyShield.BlockedHistoryGroups, privacyView));

            // 3. AiAnalystView code-behind subscription attaches and detaches with visual tree
            var aiView = new AiAnalystView { DataContext = shell.AiAnalyst };
            window.Content = aiView;
            Dispatcher.UIThread.RunJobs();
            Assert.True(HasPropertyChangedTarget(shell.AiAnalyst, aiView));

            window.Content = null;
            Dispatcher.UIThread.RunJobs();
            Assert.False(HasPropertyChangedTarget(shell.AiAnalyst, aiView));

            // 4. FirewallView detaches and re-attaches with the same DataContext
            var fwView = new FirewallView { DataContext = shell.Firewall };
            window.Content = fwView;
            Dispatcher.UIThread.RunJobs();
            Assert.Equal(1, AlertFocusSubscriberCount(shell.Firewall));

            window.Content = null;
            Dispatcher.UIThread.RunJobs();
            Assert.Equal(0, AlertFocusSubscriberCount(shell.Firewall));

            window.Content = fwView;
            Dispatcher.UIThread.RunJobs();
            Assert.Equal(1, AlertFocusSubscriberCount(shell.Firewall));

            window.Close();
        });
    }

    [Fact]
    public void Settings_constructor_does_not_write_notification_stores_during_initialization()
    {
        var timers = new FakeTimerFactory();
        using var monitor = new ConnectionMonitor(new FakeSnapshotSource(), timers);
        using var settings = new SettingsPageViewModel(
            monitor,
            serviceMode: false,
            new FixedThemeService(),
            new UnsupportedAutostartService());

        Assert.Equal(TraySettingsStore.Enabled, settings.TrayNotificationsEnabled);
        Assert.Equal(NotificationSettingsStore.Enabled, settings.NotificationsEnabled);
        Assert.Equal(BackgroundWindowSettingsStore.Enabled, settings.HideBackgroundWindows);
    }

    private static int SubscriberCount<T>(ObservableCollection<T> collection)
    {
        var field = typeof(ObservableCollection<T>)
            .GetField("CollectionChanged", BindingFlags.Instance | BindingFlags.NonPublic);
        var del = field?.GetValue(collection) as Delegate;
        return del?.GetInvocationList().Length ?? 0;
    }

    private static bool HasCollectionChangedTarget<T>(ObservableCollection<T> collection, object target)
    {
        var field = typeof(ObservableCollection<T>)
            .GetField("CollectionChanged", BindingFlags.Instance | BindingFlags.NonPublic);
        var del = field?.GetValue(collection) as Delegate;
        return del?.GetInvocationList().Any(d => ReferenceEquals(d.Target, target)) == true;
    }

    private static bool HasPropertyChangedTarget(object observable, object target)
    {
        for (var type = observable.GetType(); type is not null; type = type.BaseType)
        {
            var field = type.GetField("PropertyChanged", BindingFlags.Instance | BindingFlags.NonPublic);
            if (field is not null)
            {
                var del = field.GetValue(observable) as Delegate;
                return del?.GetInvocationList().Any(d => ReferenceEquals(d.Target, target)) == true;
            }
        }

        return false;
    }

    private static int AlertFocusSubscriberCount(FirewallPageViewModel vm)
    {
        var field = typeof(FirewallPageViewModel)
            .GetField("AlertFocusRequested", BindingFlags.Instance | BindingFlags.NonPublic);
        var del = field?.GetValue(vm) as Delegate;
        return del?.GetInvocationList().Length ?? 0;
    }

    private static bool GetTrayMonitoring(AgentsPageViewModel agents) =>
        (bool)typeof(AgentsPageViewModel)
            .GetField("_trayMonitoring", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(agents)!;

    private static FakeTimer? FindAgentTimer(FakeTimerFactory timers) =>
        timers.Created.FirstOrDefault(timer =>
            timer.Interval == TimeSpan.FromSeconds(8) ||
            timer.Interval == TimeSpan.FromSeconds(30));

    private static void TriggerProtectionProbe(ShellViewModel shell, FakeTimerFactory timers)
    {
        _ = timers;
        var method = typeof(ShellViewModel).GetMethod(
            "ProbeProtectionAsync",
            BindingFlags.Instance | BindingFlags.NonPublic);
        var args = method!.GetParameters().Length == 1 ? new object?[] { false } : null;
        var task = (Task)method.Invoke(shell, args)!;
        Assert.True(task.IsCompletedSuccessfully);
    }

    private static void AdvanceLastProtectionProbe(ShellViewModel shell)
    {
        typeof(ShellViewModel)
            .GetField("_lastProtectionProbeUtc", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(shell, DateTimeOffset.UtcNow.AddSeconds(-10));
    }

    private static BlackboxAuditEntry MakeEntry(int index) => new(
        DateTimeOffset.UtcNow.AddSeconds(-index),
        "pre_tool_call",
        "Codex",
        $"sess-{index}",
        "bash",
        $"echo {index}",
        "allow",
        "info",
        $"id-{index}",
        $"detail-{index}");

    private static SecurityPageViewModel CreateSecurity(FakeTimerFactory timers) => new(
        new FakeUi(),
        new FakeSecurityDialogs(),
        new FakeProtector(),
        timers,
        new FakeShellActions());

    private sealed class FakeSnapshotSource : IConnectionSnapshotSource
    {
        public string Name => "fake";
        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UtcNow,
                Connections = [],
                ProcessCount = 0,
                SourceName = "fake",
            });
    }

    private sealed class CountingSnapshotSource : IConnectionSnapshotSource
    {
        public ConnectionSnapshot NextSnapshot { get; set; } = new()
        {
            CapturedUtc = DateTimeOffset.UtcNow,
            Connections = [],
            ProcessCount = 0,
            SourceName = "counting",
        };

        public string Name => "counting";
        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(NextSnapshot);
    }

    private sealed class HangingServiceClient : IServiceRequestClient
    {
        public async Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
            throw new ServiceUnavailableException("OFFLINE", "cancelled");
        }
    }

    private sealed class ScriptedProtectionClient : IServiceRequestClient
    {
        public IReadOnlyList<ProtectionPendingApp> Pending { get; set; } = [];

        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            object response = command switch
            {
                IpcCommandTypes.ProtectionStatus => new ProtectionStatus
                {
                    Enabled = true,
                    ServiceElevated = false,
                    WriteGateOpen = true,
                    AccountName = "test",
                    DefaultPolicy = "Ask",
                    Pending = Pending,
                    Decisions = [],
                    AgentPaths = [],
                },
                IpcCommandTypes.ServiceHealth => new ServiceHealth
                {
                    Status = "Running",
                    UptimeSeconds = 10,
                    SourceName = "Test",
                    PollIntervalSeconds = 1,
                    ConnectionCount = 0,
                    ProcessCount = 0,
                },
                IpcCommandTypes.Capabilities => new ServiceCapabilities
                {
                    ProtocolVersion = 1,
                    Commands = [],
                    Monitoring = true,
                    FirewallWrites = false,
                    Milestone = "Test",
                },
                _ => throw new NotSupportedException($"Unexpected command: {command}"),
            };
            return Task.FromResult((T)response);
        }
    }

    private sealed class FakeTimerFactory : IUiTimerFactory
    {
        public List<FakeTimer> Created { get; } = [];

        public IUiTimer Create(TimeSpan interval)
        {
            var timer = new FakeTimer(interval);
            Created.Add(timer);
            return timer;
        }
    }

    private sealed class FakeTimer(TimeSpan interval) : IUiTimer
    {
        public TimeSpan Interval { get; set; } = interval;
        public bool IsEnabled { get; private set; }
        public event EventHandler? Tick;
        public void Start() => IsEnabled = true;
        public void StopTimer() => IsEnabled = false;
        public void Dispose() => StopTimer();
        public void FireTick() => Tick?.Invoke(this, EventArgs.Empty);
    }

    private sealed class FakeUi : IUserInteraction
    {
        public bool ConfirmResult { get; set; }

        public Task<bool> ConfirmAsync(string title, string message, string confirmLabel, bool destructive, CancellationToken cancellationToken) =>
            Task.FromResult(ConfirmResult);

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

        public Task CopyTextAsync(string text, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task OpenExternalAsync(string url, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class FakeProtector : IApiKeyProtector
    {
        public string Protect(string plaintext) => plaintext;
        public string Unprotect(string ciphertext) => ciphertext;
    }

    private sealed class FakeSecurityDialogs : ISecurityDialogService
    {
        public Task<ReputationSettings?> EditReputationAsync(ReputationSettings current, CancellationToken cancellationToken) =>
            Task.FromResult<ReputationSettings?>(null);

        public Task<CommunityFeedSettings?> EditCommunityAsync(CommunityFeedSettings current, CancellationToken cancellationToken) =>
            Task.FromResult<CommunityFeedSettings?>(null);

        public Task<bool?> ChooseAgentHookInstallationAsync(CancellationToken cancellationToken) =>
            Task.FromResult<bool?>(null);
    }

    private sealed class FakeBlackboxDialogs : IBlackboxDialogService
    {
        public Task ShowSettingsAsync(BlackboxDashboardClient client, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task ShowLogAsync(string title, string text, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<Axiom.Contracts.Threat.ThreatShareEnqueueRequest?> PromptManualThreatIndicatorAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult<Axiom.Contracts.Threat.ThreatShareEnqueueRequest?>(null);

        public Task<Axiom.Contracts.Threat.ThreatShareVerifyRequest?> PromptVerifyThreatCandidateAsync(
            Axiom.Contracts.Threat.ThreatShareCandidate candidate,
            CancellationToken cancellationToken) =>
            Task.FromResult<Axiom.Contracts.Threat.ThreatShareVerifyRequest?>(null);
    }

    private sealed class FakeShellActions : IShellActions
    {
        public void Restart()
        {
        }

        public void Shutdown()
        {
        }
    }

    private sealed class FakeDnsHelper : IDnsAdapterHelper
    {
        public Task<int> EnableAsync(string adapterName, string dnsAddress, CancellationToken cancellationToken) =>
            Task.FromResult(0);

        public Task<int> RestoreAsync(CancellationToken cancellationToken) =>
            Task.FromResult(0);
    }
}
