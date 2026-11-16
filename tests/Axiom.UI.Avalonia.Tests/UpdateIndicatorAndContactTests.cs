// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class UpdateIndicatorAndContactTests : IDisposable
{
    private readonly DirectoryInfo _tempDir =
        Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"axiom-ui-update-{Guid.NewGuid():N}"));

    public void Dispose()
    {
        if (_tempDir.Exists)
        {
            _tempDir.Delete(recursive: true);
        }
    }

    [Fact]
    public void Contact_button_opens_contact_email_and_fits_supported_window_widths()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var interaction = new RecordingInteraction();
            var store = new UpdateSettingsStore(Path.Combine(_tempDir.FullName, "updates.json"));
            using var http = new HttpClient(new StaticReleaseHandler());
            using var checker = new UpdateCheckService(new Version(0, 45, 0), store, http);
            var shell = new ShellViewModel(
                new FakeSource(),
                new FakeTimerFactory(),
                userInteraction: interaction,
                updateChecker: checker);
            var window = new MainWindow { DataContext = shell, Width = 1024, Height = 768 };
            window.Show();
            Dispatcher.UIThread.RunJobs();

            var contact = window.GetVisualDescendants()
                .OfType<Button>()
                .FirstOrDefault(button => string.Equals(button.Content as string, "Contact", StringComparison.Ordinal));
            Assert.NotNull(contact);
            Assert.True(contact.IsVisible);
            Assert.True(contact.Bounds.Width > 0 && contact.Bounds.Height > 0);
            Assert.True(shell.OpenContactCommand.CanExecute(null));

            shell.OpenContactCommand.Execute(null);
            Dispatcher.UIThread.RunJobs();

            Assert.Contains("mailto:contact@opendkg.org", interaction.OpenedUrls);

            window.Close();
            shell.Dispose();
        });
    }

    [Fact]
    public async Task Update_badge_shows_for_newer_release_opens_download_and_dismisses_cleanly()
    {
        var store = new UpdateSettingsStore(Path.Combine(_tempDir.FullName, "updates.json"));
        var handler = new StaticReleaseHandler(new
        {
            tag_name = "v0.99.0",
            draft = false,
            prerelease = false,
            published_at = "2026-11-15T10:00:00Z",
            html_url = "https://github.com/a-51-50/Axiom/releases/tag/v0.99.0",
            body = "Security hardening release.",
        });
        using var http = new HttpClient(handler);
        using var checker = new UpdateCheckService(new Version(0, 45, 0), store, http);
        await checker.CheckIfDueAsync();

        TestAppBuilder.RunOnUiThread(() =>
        {
            var interaction = new RecordingInteraction();
            var shell = new ShellViewModel(
                new FakeSource(),
                new FakeTimerFactory(),
                userInteraction: interaction,
                updateChecker: checker);
            var window = new MainWindow { DataContext = shell };
            window.Show();
            Dispatcher.UIThread.RunJobs();

            Assert.True(shell.UpdateAvailable);
            Assert.Equal("0.99.0", shell.LatestVersion);
            Assert.Equal("Axiom 0.99.0 is available", shell.UpdateTooltip);

            var updateButton = window.FindControl<Button>("UpdateButton");
            Assert.NotNull(updateButton);
            Assert.True(updateButton.IsVisible);

            shell.OpenUpdateCommand.Execute(null);
            Dispatcher.UIThread.RunJobs();
            Assert.Contains("https://github.com/a-51-50/Axiom/releases/tag/v0.99.0", interaction.OpenedUrls);

            shell.DismissUpdateCommand.Execute(null);
            Dispatcher.UIThread.RunJobs();
            Assert.False(shell.UpdateAvailable);
            Assert.False(updateButton.IsVisible);

            // Disabling the Settings toggle persists opt-out.
            shell.Settings.CheckForUpdates = false;
            Assert.False(checker.CheckForUpdates);

            window.Close();
            shell.Dispose();
        });
    }

    private sealed class StaticReleaseHandler(object? payload = null) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (payload is null)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed class RecordingInteraction : IUserInteraction
    {
        public List<string> OpenedUrls { get; } = [];

        public Task OpenExternalAsync(string url, CancellationToken cancellationToken)
        {
            OpenedUrls.Add(url);
            return Task.CompletedTask;
        }

        public Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task ShowDocumentAsync(string title, string documentText, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<bool> ConfirmAsync(string title, string message, string confirmLabel, bool destructive, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<string?> PickSaveFileAsync(string suggestedFileName, string extension, string typeName, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task<string?> PickOpenFileAsync(string title, string extension, string typeName, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task<string?> PickFolderAsync(string title, CancellationToken cancellationToken) => Task.FromResult<string?>(null);

        public Task CopyTextAsync(string text, CancellationToken cancellationToken) => Task.CompletedTask;
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
