// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Axiom.Presentation;

/// <summary>
/// Checks GitHub Releases at most once every 6 hours when opted in and exposes whether a newer
/// stable release is available. Never sends telemetry or installation IDs and never downloads binaries.
/// </summary>
public sealed class UpdateCheckService : IDisposable
{
    public const string DefaultReleasesPageUrl = "https://github.com/a-51-50/Axiom/releases";
    private const string DefaultApiUrl = "https://api.github.com/repos/a-51-50/Axiom/releases/latest";
    private const string RepositoryWebPrefix = "https://github.com/a-51-50/Axiom/";
    public static readonly TimeSpan MinimumCheckInterval = TimeSpan.FromHours(6);

    private readonly Version _currentVersion;
    private readonly UpdateSettingsStore _settingsStore;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly Uri _releaseEndpoint;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _checkGate = new(1, 1);

    private bool _checkForUpdates;
    private string _dismissedVersion;
    private string _latestVersion = string.Empty;
    private string _releaseDateText = string.Empty;
    private string _summaryText = string.Empty;
    private string _releaseUrl = DefaultReleasesPageUrl;
    private bool _isUpdateAvailable;
    private bool _disposed;

    public UpdateCheckService(
        Version currentVersion,
        UpdateSettingsStore? settingsStore = null,
        HttpClient? httpClient = null,
        Uri? releaseEndpoint = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(currentVersion);
        _currentVersion = NormalizeVersion(currentVersion);
        _settingsStore = settingsStore ?? new UpdateSettingsStore();
        _ownsHttpClient = httpClient is null;
        _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        _releaseEndpoint = releaseEndpoint ?? new Uri(DefaultApiUrl, UriKind.Absolute);
        _timeProvider = timeProvider ?? TimeProvider.System;

        var settings = _settingsStore.Load();
        _checkForUpdates = settings.CheckForUpdates;
        _dismissedVersion = NormalizeDismissed(settings.DismissedVersion);
    }

    public event EventHandler? Changed;

    public bool CheckForUpdates => _checkForUpdates;

    public string LatestVersion => _latestVersion;

    public string ReleaseDateText => _releaseDateText;

    public string SummaryText => _summaryText;

    public string ReleaseUrl => _releaseUrl;

    public string DismissedVersion => _dismissedVersion;

    public bool IsUpdateAvailable => _isUpdateAvailable;

    /// <summary>Updates the user opt-in/opt-out setting and persists it without network traffic.</summary>
    public void SetCheckForUpdatesEnabled(bool enabled)
    {
        var current = _settingsStore.Load();
        _checkForUpdates = enabled;
        _settingsStore.Save(current with { CheckForUpdates = enabled });
        if (!enabled)
        {
            ClearAvailableState();
        }
        else
        {
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }

    /// <summary>Remembers the current latest release as dismissed until an even newer release appears.</summary>
    public void Dismiss()
    {
        if (string.IsNullOrWhiteSpace(_latestVersion))
        {
            _isUpdateAvailable = false;
            Changed?.Invoke(this, EventArgs.Empty);
            return;
        }

        var current = _settingsStore.Load();
        _dismissedVersion = _latestVersion;
        _settingsStore.Save(current with { DismissedVersion = _dismissedVersion });
        _isUpdateAvailable = false;
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Checks GitHub Releases if update checking is enabled and at least <see cref="MinimumCheckInterval"/>
    /// has elapsed since the previous check attempt. Failures stay completely silent.
    /// </summary>
    public async Task<bool> CheckIfDueAsync(CancellationToken cancellationToken = default)
    {
        if (_disposed)
        {
            return false;
        }

        await _checkGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var settings = _settingsStore.Load();
            _checkForUpdates = settings.CheckForUpdates;
            _dismissedVersion = NormalizeDismissed(settings.DismissedVersion);

            if (!settings.CheckForUpdates)
            {
                ClearAvailableState();
                return false;
            }

            var now = _timeProvider.GetUtcNow();
            if (settings.LastCheckedUtc != DateTimeOffset.MinValue &&
                now - settings.LastCheckedUtc < MinimumCheckInterval)
            {
                return _isUpdateAvailable;
            }

            // Record attempt timestamp before hitting the network so rate limits, 404s, or offline restarts
            // cannot trigger retry storms against unauthenticated GitHub quotas.
            _settingsStore.Save(settings with { LastCheckedUtc = now });

            using var request = new HttpRequestMessage(HttpMethod.Get, _releaseEndpoint);
            request.Headers.UserAgent.Clear();
            request.Headers.UserAgent.Add(new ProductInfoHeaderValue("Axiom", FormatVersion(_currentVersion)));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken)
                .ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return false;
            }

            var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return ApplyReleaseJson(json);
        }
        catch (Exception exception) when (exception is
                     HttpRequestException or TaskCanceledException or OperationCanceledException or JsonException)
        {
            return false;
        }
        finally
        {
            _checkGate.Release();
        }
    }

    /// <summary>Parses a stable numeric tag such as <c>v0.17</c> or <c>0.45.0</c>, rejecting prereleases.</summary>
    public static bool TryParseStableVersion(string? rawVersion, out Version version)
    {
        version = new Version(0, 0, 0, 0);
        if (string.IsNullOrWhiteSpace(rawVersion))
        {
            return false;
        }

        var trimmed = rawVersion.Trim();
        if (trimmed.StartsWith('v') || trimmed.StartsWith('V'))
        {
            trimmed = trimmed[1..].Trim();
        }

        // Ignore semver prereleases (-alpha, -rc.1, etc.).
        if (trimmed.Contains('-', StringComparison.Ordinal))
        {
            return false;
        }

        var plusIndex = trimmed.IndexOf('+', StringComparison.Ordinal);
        if (plusIndex >= 0)
        {
            trimmed = trimmed[..plusIndex];
        }

        if (!Version.TryParse(trimmed, out var parsed) || parsed.Major < 0 || parsed.Minor < 0)
        {
            return false;
        }

        version = NormalizeVersion(parsed);
        return true;
    }

    /// <summary>Compares normalized stable versions so <c>0.17</c> and <c>0.17.0</c> are equal.</summary>
    public static bool IsNewerVersion(Version candidate, Version current)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(current);
        return NormalizeVersion(candidate) > NormalizeVersion(current);
    }

    public static string FormatVersion(Version version)
    {
        ArgumentNullException.ThrowIfNull(version);
        var normalized = NormalizeVersion(version);
        return normalized.Revision > 0
            ? $"{normalized.Major}.{normalized.Minor}.{normalized.Build}.{normalized.Revision}"
            : $"{normalized.Major}.{normalized.Minor}.{normalized.Build}";
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _checkGate.Dispose();
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }

    private bool ApplyReleaseJson(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var isDraft = root.TryGetProperty("draft", out var draftProp) && draftProp.ValueKind == JsonValueKind.True;
        var isPrerelease = root.TryGetProperty("prerelease", out var preProp) && preProp.ValueKind == JsonValueKind.True;
        if (isDraft || isPrerelease)
        {
            ClearAvailableState();
            return false;
        }

        var tagName = root.TryGetProperty("tag_name", out var tagProp) && tagProp.ValueKind == JsonValueKind.String
            ? tagProp.GetString()
            : null;
        if (!TryParseStableVersion(tagName, out var remoteVersion))
        {
            ClearAvailableState();
            return false;
        }

        if (!IsNewerVersion(remoteVersion, _currentVersion))
        {
            ClearAvailableState();
            return false;
        }

        var formattedRemote = FormatVersion(remoteVersion);
        var dateText = root.TryGetProperty("published_at", out var pubProp) &&
                       pubProp.ValueKind == JsonValueKind.String &&
                       pubProp.TryGetDateTimeOffset(out var publishedUtc)
            ? publishedUtc.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
            : string.Empty;
        var summary = root.TryGetProperty("body", out var bodyProp) && bodyProp.ValueKind == JsonValueKind.String
            ? SummarizeBody(bodyProp.GetString())
            : string.Empty;
        var htmlUrl = root.TryGetProperty("html_url", out var urlProp) &&
                      urlProp.ValueKind == JsonValueKind.String &&
                      urlProp.GetString() is { } candidateUrl &&
                      candidateUrl.StartsWith(RepositoryWebPrefix, StringComparison.OrdinalIgnoreCase)
            ? candidateUrl
            : DefaultReleasesPageUrl;

        _latestVersion = formattedRemote;
        _releaseDateText = dateText;
        _summaryText = summary;
        _releaseUrl = htmlUrl;
        _isUpdateAvailable = _checkForUpdates &&
                             !string.Equals(_dismissedVersion, formattedRemote, StringComparison.Ordinal);

        Changed?.Invoke(this, EventArgs.Empty);
        return _isUpdateAvailable;
    }

    private void ClearAvailableState()
    {
        var changed = _isUpdateAvailable || !string.IsNullOrEmpty(_latestVersion);
        _isUpdateAvailable = false;
        _latestVersion = string.Empty;
        _releaseDateText = string.Empty;
        _summaryText = string.Empty;
        _releaseUrl = DefaultReleasesPageUrl;
        if (changed)
        {
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }

    private static Version NormalizeVersion(Version version) => new(
        Math.Max(0, version.Major),
        Math.Max(0, version.Minor),
        version.Build >= 0 ? version.Build : 0,
        version.Revision >= 0 ? version.Revision : 0);

    private static string NormalizeDismissed(string? version) =>
        TryParseStableVersion(version, out var parsed) ? FormatVersion(parsed) : string.Empty;

    private static string SummarizeBody(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return string.Empty;
        }

        foreach (var rawLine in body.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim().TrimStart('#', '-', '*', '>').Trim();
            if (string.IsNullOrWhiteSpace(line) ||
                line.StartsWith("Released:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            const int maxLength = 200;
            return line.Length <= maxLength
                ? line
                : line[..(maxLength - 3)].TrimEnd() + "...";
        }

        return string.Empty;
    }
}
