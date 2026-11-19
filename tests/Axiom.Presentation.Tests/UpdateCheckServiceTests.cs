// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class UpdateCheckServiceTests : IDisposable
{
    private readonly DirectoryInfo _tempDir =
        Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"axiom-update-test-{Guid.NewGuid():N}"));

    public void Dispose()
    {
        if (_tempDir.Exists)
        {
            _tempDir.Delete(recursive: true);
        }
    }

    [Theory]
    [InlineData("0.17", "0.17.0", false)]
    [InlineData("v0.17.0", "0.17", false)]
    [InlineData("v0.45.0", "0.45.0", false)]
    [InlineData("v0.44.9", "0.45.0", false)]
    [InlineData("v0.46.0", "0.45.0", true)]
    [InlineData("1.0.0", "0.45.0", true)]
    public void Stable_version_comparison_handles_two_and_three_part_versions(
        string candidateRaw,
        string currentRaw,
        bool expectedNewer)
    {
        Assert.True(UpdateCheckService.TryParseStableVersion(candidateRaw, out var candidate));
        Assert.True(UpdateCheckService.TryParseStableVersion(currentRaw, out var current));
        Assert.Equal(expectedNewer, UpdateCheckService.IsNewerVersion(candidate, current));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("v0.46.0-rc.1")]
    [InlineData("1.0.0-beta")]
    [InlineData("not-a-version")]
    public void Prerelease_and_invalid_tags_are_rejected(string? raw)
    {
        Assert.False(UpdateCheckService.TryParseStableVersion(raw, out _));
    }

    [Fact]
    public async Task Newer_stable_release_sets_badge_and_dismiss_hides_until_even_newer_version()
    {
        var store = new UpdateSettingsStore(Path.Combine(_tempDir.FullName, "updates.json"));
        var clock = new AdjustableTimeProvider(new DateTimeOffset(2026, 11, 15, 10, 0, 0, TimeSpan.Zero));
        var handler = new QueueHandler();
        handler.EnqueueJson(new
        {
            tag_name = "v0.46.0",
            draft = false,
            prerelease = false,
            published_at = "2026-11-15T09:00:00Z",
            html_url = "https://github.com/OpenDKG/Axiom/releases/tag/v0.46.0",
            body = "# Axiom 0.46.0\n\nFixes startup layout.\n",
        });

        using var http = new HttpClient(handler);
        using var service = new UpdateCheckService(new Version(0, 45, 0), store, http, timeProvider: clock);

        Assert.True(await service.CheckIfDueAsync());
        Assert.True(service.IsUpdateAvailable);
        Assert.Equal("0.46.0", service.LatestVersion);
        Assert.Equal("2026-11-15", service.ReleaseDateText);
        Assert.Equal("Axiom 0.46.0", service.SummaryText);
        Assert.Equal("https://github.com/OpenDKG/Axiom/releases/tag/v0.46.0", service.ReleaseUrl);
        Assert.Equal(new Uri("https://api.github.com/repos/OpenDKG/Axiom/releases/latest"), handler.LastRequestUri);

        service.Dismiss();
        Assert.False(service.IsUpdateAvailable);
        Assert.Equal("0.46.0", service.DismissedVersion);

        // Next 6h check for the same dismissed version remains hidden.
        clock.Advance(TimeSpan.FromHours(7));
        handler.EnqueueJson(new
        {
            tag_name = "v0.46.0",
            draft = false,
            prerelease = false,
            html_url = "https://github.com/OpenDKG/Axiom/releases/tag/v0.46.0",
            body = "Same release.",
        });
        Assert.False(await service.CheckIfDueAsync());
        Assert.False(service.IsUpdateAvailable);

        // Even newer release brings the badge back.
        clock.Advance(TimeSpan.FromHours(7));
        handler.EnqueueJson(new
        {
            tag_name = "v0.47.0",
            draft = false,
            prerelease = false,
            html_url = "https://github.com/a-51-50/Axiom/releases/tag/v0.47.0",
            body = "New release summary.",
        });
        Assert.True(await service.CheckIfDueAsync());
        Assert.True(service.IsUpdateAvailable);
        Assert.Equal("0.47.0", service.LatestVersion);
        Assert.Equal("https://github.com/OpenDKG/Axiom/releases", service.ReleaseUrl);
    }

    [Fact]
    public async Task Prereleases_drafts_current_and_older_releases_show_no_update()
    {
        var store = new UpdateSettingsStore(Path.Combine(_tempDir.FullName, "updates.json"));
        var clock = new AdjustableTimeProvider(new DateTimeOffset(2026, 11, 15, 10, 0, 0, TimeSpan.Zero));
        var handler = new QueueHandler();
        handler.EnqueueJson(new { tag_name = "v0.46.0", draft = false, prerelease = true });
        handler.EnqueueJson(new { tag_name = "v0.46.0", draft = true, prerelease = false });
        handler.EnqueueJson(new { tag_name = "v0.45", draft = false, prerelease = false });
        handler.EnqueueJson(new { tag_name = "v0.44.0", draft = false, prerelease = false });

        using var http = new HttpClient(handler);
        using var service = new UpdateCheckService(new Version(0, 45, 0), store, http, timeProvider: clock);

        for (var i = 0; i < 4; i++)
        {
            Assert.False(await service.CheckIfDueAsync());
            Assert.False(service.IsUpdateAvailable);
            clock.Advance(TimeSpan.FromHours(7));
        }

        Assert.Equal(4, handler.RequestCount);
    }

    [Fact]
    public async Task Failures_are_silent_and_cooldown_prevents_retry_storms()
    {
        var store = new UpdateSettingsStore(Path.Combine(_tempDir.FullName, "updates.json"));
        var clock = new AdjustableTimeProvider(new DateTimeOffset(2026, 11, 15, 10, 0, 0, TimeSpan.Zero));
        var handler = new QueueHandler();
        handler.EnqueueException(new HttpRequestException("Offline"));
        handler.EnqueueStatus(HttpStatusCode.NotFound);
        handler.EnqueueJson(new { tag_name = "v0.99.0" });

        using var http = new HttpClient(handler);
        using var service = new UpdateCheckService(new Version(0, 45, 0), store, http, timeProvider: clock);

        Assert.False(await service.CheckIfDueAsync());
        Assert.False(service.IsUpdateAvailable);
        Assert.Equal(1, handler.RequestCount);

        // Cooldown prevents repeating network calls within 6 hours.
        clock.Advance(TimeSpan.FromHours(2));
        Assert.False(await service.CheckIfDueAsync());
        Assert.Equal(1, handler.RequestCount);

        // Next check after 6 hours handles HTTP 404 silently.
        clock.Advance(TimeSpan.FromHours(5));
        Assert.False(await service.CheckIfDueAsync());
        Assert.False(service.IsUpdateAvailable);
        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task Disabling_check_for_updates_makes_zero_network_requests()
    {
        var store = new UpdateSettingsStore(Path.Combine(_tempDir.FullName, "updates.json"));
        var handler = new QueueHandler();
        handler.EnqueueJson(new { tag_name = "v0.99.0" });

        using var http = new HttpClient(handler);
        using var service = new UpdateCheckService(new Version(0, 45, 0), store, http);

        service.SetCheckForUpdatesEnabled(false);
        Assert.False(service.CheckForUpdates);
        Assert.False(await service.CheckIfDueAsync());
        Assert.False(service.IsUpdateAvailable);
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task Disposing_or_opting_out_during_inflight_check_does_not_throw_or_republish()
    {
        var store = new UpdateSettingsStore(Path.Combine(_tempDir.FullName, "updates.json"));
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var http = new HttpClient(new BlockingHandler(gate.Task, """{"tag_name":"v9.9.9","draft":false,"prerelease":false}"""));
        var service = new UpdateCheckService(new Version(1, 0, 0), store, http);

        var inflight = service.CheckIfDueAsync();
        service.SetCheckForUpdatesEnabled(false);
        gate.SetResult();
        Assert.False(await inflight);
        Assert.False(service.IsUpdateAvailable);
        Assert.Equal(string.Empty, service.LatestVersion);

        service.Dispose();
        Assert.False(await service.CheckIfDueAsync());
    }

    private sealed class BlockingHandler(Task releaseTask, string json) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await releaseTask.WaitAsync(cancellationToken).ConfigureAwait(false);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
        }
    }

    private sealed class AdjustableTimeProvider(DateTimeOffset startUtc) : TimeProvider
    {
        private DateTimeOffset _now = startUtc;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan delta) => _now += delta;
    }

    private sealed class QueueHandler : HttpMessageHandler
    {
        private readonly Queue<Func<HttpResponseMessage>> _responses = new();

        public int RequestCount { get; private set; }
        public Uri? LastRequestUri { get; private set; }

        public void EnqueueJson(object payload) =>
            _responses.Enqueue(() => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"),
            });

        public void EnqueueStatus(HttpStatusCode status) =>
            _responses.Enqueue(() => new HttpResponseMessage(status));

        public void EnqueueException(Exception exception) =>
            _responses.Enqueue(() => throw exception);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            LastRequestUri = request.RequestUri;
            return Task.FromResult(_responses.Count > 0
                ? _responses.Dequeue()()
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}
