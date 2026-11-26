// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
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

        // Cooldown prevents repeating network calls within 15 minutes.
        clock.Advance(TimeSpan.FromMinutes(10));
        Assert.False(await service.CheckIfDueAsync());
        Assert.Equal(1, handler.RequestCount);

        // Next check after 15 minutes handles HTTP 404 silently.
        clock.Advance(TimeSpan.FromMinutes(6));
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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Installer_download_keeps_only_bytes_verified_for_the_detected_release(bool tampered)
    {
        const string url = "https://github.com/OpenDKG/Axiom/releases/download/v1.4.5/Axiom-Setup.exe";
        var expected = new byte[150 * 1024];
        var returned = expected.ToArray();
        if (tampered)
        {
            returned[0] ^= 1;
        }

        var store = new UpdateSettingsStore(Path.Combine(_tempDir.FullName, "updates.json"));
        var handler = new QueueHandler();
        handler.EnqueueJson(new
        {
            tag_name = "v1.4.5",
            assets = new[]
            {
                new { name = "Axiom-Setup.exe", browser_download_url = url, size = expected.Length,
                    digest = "sha256:" + Convert.ToHexString(SHA256.HashData(expected)) },
            },
        });
        handler.EnqueueBytes(returned);
        using var http = new HttpClient(handler);
        using var service = new UpdateCheckService(new Version(1, 4, 4), store, http);

        Assert.True(await service.CheckIfDueAsync());
        Assert.Equal(1, handler.RequestCount);
        var downloadDir = Path.Combine(_tempDir.FullName, "updates");
        var progress = new RecordedProgress();
        if (tampered)
        {
            await Assert.ThrowsAsync<InvalidDataException>(
                () => service.DownloadWindowsInstallerAsync(CancellationToken.None, progress));
            Assert.Empty(Directory.GetFiles(downloadDir));
        }
        else
        {
            var path = await service.DownloadWindowsInstallerAsync(CancellationToken.None, progress);
            Assert.Equal(Path.Combine(downloadDir, "Axiom-Setup.exe"), path);
            Assert.Equal(expected, await File.ReadAllBytesAsync(path));
        }

        Assert.Equal(0, progress.Values[0]);
        Assert.Equal(100, progress.Values[^1]);
        Assert.True(progress.Values.Count > 2);
        Assert.Equal(progress.Values.Distinct().Order(), progress.Values);
        Assert.Equal(new Uri(url), handler.LastRequestUri);
    }

    [Fact]
    public async Task Release_notes_preserve_multiline_changelog_and_check_now_bypasses_cooldown()
    {
        var store = new UpdateSettingsStore(Path.Combine(_tempDir.FullName, "updates.json"));
        var clock = new AdjustableTimeProvider(new DateTimeOffset(2026, 11, 21, 10, 0, 0, TimeSpan.Zero));
        var handler = new QueueHandler();
        handler.EnqueueJson(new
        {
            tag_name = "v1.4.8",
            draft = false,
            prerelease = false,
            published_at = "2026-11-21T12:00:00Z",
            html_url = "https://github.com/OpenDKG/Axiom/releases/tag/v1.4.8",
            body = "## What's New\n- Fix **OpenChamber** hook registration\n- Add exact dates in findings",
        });

        using var http = new HttpClient(handler);
        using var service = new UpdateCheckService(new Version(1, 4, 7), store, http, timeProvider: clock);

        // Prime cooldown with a failed check first.
        handler.EnqueueJson(new
        {
            tag_name = "v1.4.8",
            draft = false,
            prerelease = false,
            published_at = "2026-11-21T12:00:00Z",
            html_url = "https://github.com/OpenDKG/Axiom/releases/tag/v1.4.8",
            body = "## What's New\n- Fix **OpenChamber** hook registration\n- Add exact dates in findings",
        });

        Assert.True(await service.CheckIfDueAsync());
        Assert.Equal("What's New", service.SummaryText);
        service.Dismiss();
        Assert.False(service.IsUpdateAvailable);

        // Within 30 minutes, CheckNowAsync bypasses cooldown and dismissed state.
        clock.Advance(TimeSpan.FromMinutes(10));
        Assert.True(await service.CheckNowAsync());
        Assert.True(service.LastCheckSucceeded);
        Assert.True(service.IsUpdateAvailable);
        Assert.Contains("• Fix OpenChamber hook registration", service.ReleaseNotesText, StringComparison.Ordinal);
        Assert.Contains("• Add exact dates in findings", service.ReleaseNotesText, StringComparison.Ordinal);
        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task CheckOnStartupAsync_bypasses_cooldown_while_honoring_opt_out_and_dismissed()
    {
        var store = new UpdateSettingsStore(Path.Combine(_tempDir.FullName, "updates.json"));
        var clock = new AdjustableTimeProvider(new DateTimeOffset(2026, 11, 21, 10, 0, 0, TimeSpan.Zero));
        var handler = new QueueHandler();
        handler.EnqueueJson(new { tag_name = "v1.4.8", draft = false, prerelease = false });
        handler.EnqueueJson(new { tag_name = "v1.4.9", draft = false, prerelease = false });
        handler.EnqueueJson(new { tag_name = "v1.4.9", draft = false, prerelease = false });

        using var http = new HttpClient(handler);
        using var service = new UpdateCheckService(new Version(1, 4, 7), store, http, timeProvider: clock);

        Assert.True(await service.CheckIfDueAsync());
        Assert.Equal("1.4.8", service.LatestVersion);

        // Even 1 minute later (within cooldown), startup check immediately detects v1.4.9.
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.True(await service.CheckOnStartupAsync());
        Assert.Equal("1.4.9", service.LatestVersion);
        Assert.Equal(2, handler.RequestCount);

        // Dismissed version remains dismissed across startup checks.
        service.Dismiss();
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.False(await service.CheckOnStartupAsync());
        Assert.False(service.IsUpdateAvailable);
        Assert.Equal(3, handler.RequestCount);

        // When automatic update checks are disabled, CheckOnStartupAsync makes zero network requests.
        service.SetCheckForUpdatesEnabled(false);
        Assert.False(await service.CheckOnStartupAsync());
        Assert.Equal(3, handler.RequestCount);
    }

    [Fact]
    public async Task Release_notes_strip_links_issue_numbers_subbullets_and_downloads_section()
    {
        var store = new UpdateSettingsStore(Path.Combine(_tempDir.FullName, "updates.json"));
        var handler = new QueueHandler();
        handler.EnqueueJson(new
        {
            tag_name = "v1.5.0",
            draft = false,
            prerelease = false,
            published_at = "2026-11-23T15:00:00Z",
            html_url = "https://github.com/OpenDKG/Axiom/releases/tag/v1.5.0",
            body = """
                # Axiom 1.5.0

                - **Clean uninstall & downgrade protection (#31, #32)**:
                  - Sub-bullet detail that should not clutter the popup.
                - **Privacy improvements (#30, #33)** across [README.md](../../README.md) and settings.

                ## Downloads

                - Windows x64 installer (`Axiom-Setup.exe`).
                """,
        });

        using var http = new HttpClient(handler);
        using var service = new UpdateCheckService(new Version(1, 4, 9), store, http);

        Assert.True(await service.CheckNowAsync());
        Assert.DoesNotContain("Axiom 1.5.0", service.ReleaseNotesText, StringComparison.Ordinal);
        Assert.DoesNotContain("../../README.md", service.ReleaseNotesText, StringComparison.Ordinal);
        Assert.DoesNotContain("(#31", service.ReleaseNotesText, StringComparison.Ordinal);
        Assert.DoesNotContain("Sub-bullet detail", service.ReleaseNotesText, StringComparison.Ordinal);
        Assert.DoesNotContain("Downloads", service.ReleaseNotesText, StringComparison.Ordinal);
        Assert.DoesNotContain("Axiom-Setup.exe", service.ReleaseNotesText, StringComparison.Ordinal);
        Assert.Contains("• Clean uninstall & downgrade protection", service.ReleaseNotesText, StringComparison.Ordinal);
        Assert.Contains("• Privacy improvements across README.md and settings.", service.ReleaseNotesText, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Axiom-Setup.exe", true, false, false, true)]
    [InlineData("axiom-firewall_1.5.0_amd64.deb", true, false, false, false)]
    [InlineData("axiom-firewall_1.5.0_amd64.deb", false, true, false, true)]
    [InlineData("Axiom-Setup.exe", false, true, false, false)]
    [InlineData("Axiom-1.5.0-26-osx-x64-adhoc.zip", false, false, true, true)]
    [InlineData("Axiom-1.5.0-win-x64.zip", false, false, true, false)]
    [InlineData(null, true, false, false, false)]
    public void IsMatchingPlatformAsset_selects_expected_asset_per_operating_system(
        string? assetName,
        bool isWindows,
        bool isLinux,
        bool isMacOS,
        bool expected)
    {
        Assert.Equal(expected, UpdateCheckService.IsMatchingPlatformAsset(assetName, isWindows, isLinux, isMacOS));
    }

    [Fact]
    public async Task NotModified_304_keeps_update_state_and_marks_check_succeeded()
    {
        var store = new UpdateSettingsStore(Path.Combine(_tempDir.FullName, "updates.json"));
        var clock = new AdjustableTimeProvider(new DateTimeOffset(2026, 11, 23, 12, 0, 0, TimeSpan.Zero));
        var handler = new QueueHandler();
        handler.EnqueueResponse(() =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new { tag_name = "v1.5.0", draft = false, prerelease = false }), Encoding.UTF8, "application/json"),
            };
            response.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue("\"v150-etag\"");
            return response;
        });
        handler.EnqueueStatus(HttpStatusCode.NotModified);

        using var http = new HttpClient(handler);
        using var service = new UpdateCheckService(new Version(1, 4, 9), store, http, timeProvider: clock);

        Assert.True(await service.CheckIfDueAsync());
        Assert.True(service.IsUpdateAvailable);
        Assert.Equal("1.5.0", service.LatestVersion);

        clock.Advance(TimeSpan.FromMinutes(16));
        Assert.True(await service.CheckIfDueAsync());
        Assert.True(service.LastCheckSucceeded);
        Assert.True(service.IsUpdateAvailable);
        Assert.Equal("\"v150-etag\"", handler.LastIfNoneMatch);
        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task Reenabling_check_for_updates_clears_stale_etag_so_304_cannot_hide_update()
    {
        var store = new UpdateSettingsStore(Path.Combine(_tempDir.FullName, "updates.json"));
        var clock = new AdjustableTimeProvider(new DateTimeOffset(2026, 11, 21, 10, 0, 0, TimeSpan.Zero));
        var handler = new QueueHandler();
        handler.EnqueueResponse(() =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new { tag_name = "v1.5.0", draft = false, prerelease = false }), Encoding.UTF8, "application/json"),
            };
            response.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue("\"v150-etag\"");
            return response;
        });
        handler.EnqueueJson(new { tag_name = "v1.5.0", draft = false, prerelease = false });

        using var http = new HttpClient(handler);
        using var service = new UpdateCheckService(new Version(1, 4, 9), store, http, timeProvider: clock);

        Assert.True(await service.CheckIfDueAsync());
        Assert.True(service.IsUpdateAvailable);

        service.SetCheckForUpdatesEnabled(false);
        Assert.False(service.IsUpdateAvailable);

        service.SetCheckForUpdatesEnabled(true);
        clock.Advance(TimeSpan.FromMinutes(16));
        Assert.True(await service.CheckIfDueAsync());
        Assert.Null(handler.LastIfNoneMatch);
        Assert.True(service.IsUpdateAvailable);
        Assert.Equal("1.5.0", service.LatestVersion);
        Assert.Equal(2, handler.RequestCount);
    }

    private sealed class RecordedProgress : IProgress<int>
    {
        public List<int> Values { get; } = [];

        public void Report(int value) => Values.Add(value);
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
        public string? LastIfNoneMatch { get; private set; }

        public void EnqueueResponse(Func<HttpResponseMessage> factory) =>
            _responses.Enqueue(factory);

        public void EnqueueJson(object payload) =>
            _responses.Enqueue(() => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"),
            });

        public void EnqueueStatus(HttpStatusCode status) =>
            _responses.Enqueue(() => new HttpResponseMessage(status));

        public void EnqueueBytes(byte[] bytes) =>
            _responses.Enqueue(() => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(bytes),
            });

        public void EnqueueException(Exception exception) =>
            _responses.Enqueue(() => throw exception);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            LastRequestUri = request.RequestUri;
            LastIfNoneMatch = request.Headers.IfNoneMatch.FirstOrDefault()?.Tag;
            return Task.FromResult(_responses.Count > 0
                ? _responses.Dequeue()()
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}
