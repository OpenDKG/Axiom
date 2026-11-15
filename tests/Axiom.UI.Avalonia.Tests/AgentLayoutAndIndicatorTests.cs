// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Http;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Axiom.Contracts.Blackbox;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Threat;
using Axiom.Presentation;
using Axiom.UI.Avalonia.Views;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class AgentLayoutAndIndicatorTests
{
    [Fact]
    public void Agent_protection_settles_indicator_preview_when_blackbox_is_offline()
    {
        _ = typeof(MainWindow).Assembly;
        TestAppBuilder.RunOnUiThread(() =>
        {
            using var security = new SecurityPageViewModel(
                new DummyInteraction(),
                new UnsupportedSecurityDialogs(),
                new UnsupportedApiKeyProtector(),
                new TestTimerFactory(),
                new UnsupportedShellActions());
            using var http = new HttpClient(new FailingHandler());
            using var offlineBlackbox = new BlackboxDashboardClient(http, new Uri("http://127.0.0.1:4110/"));

            using var withoutService = new AgentsPageViewModel(
                security,
                agentSessions: null,
                new DummyInteraction(),
                new UnsupportedBlackboxDialogs(),
                new TestTimerFactory(),
                serviceClient: null,
                blackboxClient: offlineBlackbox);

            var noServiceTask = withoutService.RefreshCommand.ExecuteAsync(null);
            PumpUntil(() => noServiceTask.IsCompleted);
            noServiceTask.GetAwaiter().GetResult();

            Assert.DoesNotContain("Loading the indicator preview", withoutService.ThreatShareQueueText, StringComparison.Ordinal);
            Assert.Equal("Indicator preview needs the local Axiom service.", withoutService.ThreatShareQueueText);

            using var withService = new AgentsPageViewModel(
                security,
                agentSessions: null,
                new DummyInteraction(),
                new UnsupportedBlackboxDialogs(),
                new TestTimerFactory(),
                serviceClient: new EmptyQueueServiceClient(),
                blackboxClient: offlineBlackbox);

            var withServiceTask = withService.RefreshCommand.ExecuteAsync(null);
            PumpUntil(() => withServiceTask.IsCompleted);
            withServiceTask.GetAwaiter().GetResult();

            Assert.DoesNotContain("Loading the indicator preview", withService.ThreatShareQueueText, StringComparison.Ordinal);
            Assert.Equal("Blackbox dashboard is offline or not responding.", withService.HealthStatusText);
        });
    }

    [Fact]
    public void Main_window_header_and_agent_cards_fit_at_1024x768_without_clipping()
    {
        _ = typeof(MainWindow).Assembly;
        TestAppBuilder.RunOnUiThread(() =>
        {
            using var shell = new ShellViewModel(new FakeConnectionSource(), new TestTimerFactory());
            var window = new MainWindow
            {
                Width = 1024,
                Height = 768,
                DataContext = shell,
            };

            try
            {
                window.Show();
                Dispatcher.UIThread.RunJobs();

                var agentsPage = Assert.Single(shell.Pages.OfType<AgentsPageViewModel>());
                shell.SelectedPage = agentsPage;
                window.UpdateLayout();
                Dispatcher.UIThread.RunJobs();

                var headerTitle = window.FindControl<TextBlock>("HeaderPageTitle");
                Assert.NotNull(headerTitle);
                Assert.True(headerTitle!.Bounds.Width >= 160, $"HeaderPageTitle width was {headerTitle.Bounds.Width}");

                var agentsView = Assert.IsType<AgentsView>(window.Content is null ? null : FindDescendant<AgentsView>(window));
                var moduleGrid = agentsView.FindControl<Grid>("ModuleCardsGrid");
                var dkgCard = agentsView.FindControl<Border>("DkgModuleCard");
                var blackboxCard = agentsView.FindControl<Border>("BlackboxModuleCard");

                Assert.NotNull(moduleGrid);
                Assert.NotNull(dkgCard);
                Assert.NotNull(blackboxCard);

                Assert.True(dkgCard!.Bounds.Width > 0);
                Assert.True(blackboxCard!.Bounds.Width > 0);
                Assert.True(
                    dkgCard.Bounds.Right <= blackboxCard.Bounds.Left + 0.5,
                    $"DKG card right {dkgCard.Bounds.Right} overlapped Blackbox card left {blackboxCard.Bounds.Left}");
                Assert.True(
                    blackboxCard.Bounds.Right <= moduleGrid!.Bounds.Width + 0.5,
                    $"Blackbox card right {blackboxCard.Bounds.Right} exceeded grid width {moduleGrid.Bounds.Width}");
            }
            finally
            {
                window.Close();
            }
        });
    }

    private static T? FindDescendant<T>(Visual root) where T : class
    {
        foreach (var child in root.GetVisualChildren())
        {
            if (child is T match)
            {
                return match;
            }

            if (FindDescendant<T>(child) is { } nested)
            {
                return nested;
            }
        }

        return null;
    }

    private static void PumpUntil(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("Timed out waiting for headless UI refresh.");
            }

            Dispatcher.UIThread.RunJobs();
            Thread.Sleep(5);
        }
    }

    private sealed class FailingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("Blackbox dashboard is offline.");
    }

    private sealed class EmptyQueueServiceClient : IServiceRequestClient
    {
        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            object result = command switch
            {
                IpcCommandTypes.ThreatShareStatus => new ThreatShareQueueStatus
                {
                    Pending = 0,
                    Submitted = 0,
                    TodaySubmitted = 0,
                    Detail = "No indicators queued.",
                    Items = [],
                },
                _ => throw new ServiceUnavailableException(IpcErrorCodes.NotSupported, "not supported"),
            };

            return Task.FromResult((T)result);
        }
    }

    private sealed class FakeConnectionSource : IConnectionSnapshotSource
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

    private sealed class DummyInteraction : IUserInteraction
    {
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

        public Task CopyTextAsync(string text, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task OpenExternalAsync(string url, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class TestTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new TestTimer(interval);

        private sealed class TestTimer(TimeSpan interval) : IUiTimer
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
