// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Axiom.Contracts;

namespace Axiom.Presentation;

/// <summary>
/// Checks GitHub Releases on startup and at most once every 30 minutes when opted in, and exposes
/// whether a newer stable release is available. Installer downloads require an explicit user action.
/// </summary>
public sealed class UpdateCheckService : IDisposable
{
    public const string DefaultReleasesPageUrl = ProjectLinks.Releases;
    private const string RepositoryWebPrefix = DefaultReleasesPageUrl + "/tag/";
    private const string WindowsInstallerName = "Axiom-Setup.exe";
    private const long MaxInstallerBytes = 512L * 1024 * 1024;
    public static readonly TimeSpan MinimumCheckInterval = TimeSpan.FromMinutes(30);

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
    private string _releaseNotesText = string.Empty;
    private string _releaseUrl = DefaultReleasesPageUrl;
    private InstallerAsset? _windowsInstaller;
    private bool _isUpdateAvailable;
    private bool _lastCheckSucceeded;
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
        _releaseEndpoint = releaseEndpoint ?? new Uri(ProjectLinks.LatestReleaseApi, UriKind.Absolute);
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

    public string ReleaseNotesText => _releaseNotesText;

    public string ReleaseUrl => _releaseUrl;

    public string DismissedVersion => _dismissedVersion;

    public bool IsUpdateAvailable => _isUpdateAvailable;

    public bool LastCheckSucceeded => _lastCheckSucceeded;

    private sealed record InstallerAsset(Uri DownloadUri, long Size, string Sha256);

    /// <summary>Downloads the exact Windows asset for the detected release and verifies its GitHub digest.</summary>
    public async Task<string> DownloadWindowsInstallerAsync(
        CancellationToken cancellationToken,
        IProgress<int>? progress = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var asset = _windowsInstaller;
        if (!_isUpdateAvailable || asset is null)
        {
            throw new InvalidOperationException("This release does not provide a verifiable Windows installer.");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(15));
        var token = timeout.Token;
        var settingsDirectory = Path.GetDirectoryName(Path.GetFullPath(_settingsStore.SettingsPath))!;
        var directory = Path.Combine(settingsDirectory, "updates");
        Directory.CreateDirectory(directory);
        var installerPath = Path.Combine(directory, WindowsInstallerName);
        var partialPath = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".partial");
        progress?.Report(0);
        try
        {
            using var response = await _http.GetAsync(
                asset.DownloadUri, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is long contentLength && contentLength != asset.Size)
            {
                throw new InvalidDataException("The installer size does not match the published release.");
            }

            await using var input = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long total = 0;
            var reportedPercentage = 0;
            await using (var output = new FileStream(
                             partialPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                             bufferSize: 64 * 1024, useAsync: true))
            {
                var buffer = new byte[64 * 1024];
                int read;
                while ((read = await input.ReadAsync(buffer, token).ConfigureAwait(false)) != 0)
                {
                    total += read;
                    if (total > asset.Size)
                    {
                        throw new InvalidDataException("The installer is larger than the published release.");
                    }

                    hash.AppendData(buffer, 0, read);
                    await output.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
                    var percentage = (int)(total * 100 / asset.Size);
                    if (percentage > reportedPercentage)
                    {
                        reportedPercentage = percentage;
                        progress?.Report(percentage);
                    }
                }
            }

            if (total != asset.Size ||
                !string.Equals(Convert.ToHexString(hash.GetHashAndReset()), asset.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("The installer failed SHA-256 verification.");
            }

            token.ThrowIfCancellationRequested();
            File.Move(partialPath, installerPath, overwrite: true);
            return installerPath;
        }
        finally
        {
            File.Delete(partialPath);
        }
    }

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
    public Task<bool> CheckIfDueAsync(CancellationToken cancellationToken = default) =>
        CheckCoreAsync(force: false, bypassCooldown: false, cancellationToken);

    /// <summary>
    /// Checks GitHub Releases immediately at startup when automatic update checking is enabled,
    /// bypassing the interval cooldown while still honoring the user's dismissed version.
    /// </summary>
    public Task<bool> CheckOnStartupAsync(CancellationToken cancellationToken = default) =>
        CheckCoreAsync(force: false, bypassCooldown: true, cancellationToken);

    /// <summary>
    /// Checks GitHub Releases immediately when requested by the user, bypassing the interval cooldown.
    /// </summary>
    public Task<bool> CheckNowAsync(CancellationToken cancellationToken = default) =>
        CheckCoreAsync(force: true, bypassCooldown: true, cancellationToken);

    private async Task<bool> CheckCoreAsync(bool force, bool bypassCooldown, CancellationToken cancellationToken)
    {
        if (_disposed)
        {
            return false;
        }

        var entered = false;
        try
        {
            await _checkGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            if (_disposed)
            {
                return false;
            }

            var settings = _settingsStore.Load();
            _checkForUpdates = settings.CheckForUpdates;
            _dismissedVersion = force ? string.Empty : NormalizeDismissed(settings.DismissedVersion);

            if (!force && !settings.CheckForUpdates)
            {
                ClearAvailableState();
                return false;
            }

            var now = _timeProvider.GetUtcNow();
            if (!force &&
                !bypassCooldown &&
                settings.LastCheckedUtc != DateTimeOffset.MinValue &&
                now - settings.LastCheckedUtc < MinimumCheckInterval)
            {
                return _isUpdateAvailable;
            }

            // Record attempt timestamp before hitting the network so rate limits, 404s, or offline restarts
            // cannot trigger retry storms against unauthenticated GitHub quotas.
            _settingsStore.Save(settings with
            {
                LastCheckedUtc = now,
                DismissedVersion = force ? string.Empty : settings.DismissedVersion,
            });
            _lastCheckSucceeded = false;

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
            if (_disposed || (!force && !_checkForUpdates))
            {
                return false;
            }

            return ApplyReleaseJson(json, force);
        }
        catch (Exception exception) when (exception is
                     HttpRequestException or TaskCanceledException or OperationCanceledException or
                     JsonException or ObjectDisposedException)
        {
            _lastCheckSucceeded = false;
            return false;
        }
        finally
        {
            if (entered)
            {
                try
                {
                    _checkGate.Release();
                }
                catch (ObjectDisposedException)
                {
                }
            }
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

    private bool ApplyReleaseJson(string json, bool force = false)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        _lastCheckSucceeded = true;
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
        var rawBody = root.TryGetProperty("body", out var bodyProp) && bodyProp.ValueKind == JsonValueKind.String
            ? bodyProp.GetString()
            : null;
        var summary = SummarizeBody(rawBody);
        var releaseNotes = FormatReleaseNotes(rawBody);
        var htmlUrl = root.TryGetProperty("html_url", out var urlProp) &&
                      urlProp.ValueKind == JsonValueKind.String &&
                      urlProp.GetString() is { } candidateUrl &&
                      candidateUrl.StartsWith(RepositoryWebPrefix, StringComparison.OrdinalIgnoreCase)
            ? candidateUrl
            : DefaultReleasesPageUrl;

        _latestVersion = formattedRemote;
        _releaseDateText = dateText;
        _summaryText = summary;
        _releaseNotesText = releaseNotes;
        _releaseUrl = htmlUrl;
        _windowsInstaller = ReadWindowsInstaller(root, tagName!);
        _isUpdateAvailable = (_checkForUpdates || force) &&
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
        _releaseNotesText = string.Empty;
        _releaseUrl = DefaultReleasesPageUrl;
        _windowsInstaller = null;
        if (changed)
        {
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }

    private static InstallerAsset? ReadWindowsInstaller(JsonElement release, string tag)
    {
        if (!release.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var downloadUri = new Uri(
            $"{DefaultReleasesPageUrl}/download/{Uri.EscapeDataString(tag)}/{WindowsInstallerName}");
        foreach (var asset in assets.EnumerateArray())
        {
            if (asset.ValueKind != JsonValueKind.Object ||
                !asset.TryGetProperty("name", out var name) ||
                name.ValueKind != JsonValueKind.String ||
                !string.Equals(name.GetString(), WindowsInstallerName, StringComparison.Ordinal))
            {
                continue;
            }

            if (!asset.TryGetProperty("browser_download_url", out var url) ||
                url.ValueKind != JsonValueKind.String ||
                !string.Equals(url.GetString(), downloadUri.AbsoluteUri, StringComparison.Ordinal) ||
                !asset.TryGetProperty("size", out var length) ||
                length.ValueKind != JsonValueKind.Number ||
                !length.TryGetInt64(out var size) || size <= 0 || size > MaxInstallerBytes ||
                !asset.TryGetProperty("digest", out var digest) ||
                digest.ValueKind != JsonValueKind.String ||
                digest.GetString() is not { Length: 71 } digestText ||
                !digestText.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) ||
                !digestText[7..].All(Uri.IsHexDigit))
            {
                return null;
            }

            return new InstallerAsset(downloadUri, size, digestText[7..]);
        }

        return null;
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

    private static string FormatReleaseNotes(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return string.Empty;
        }

        const int maxLength = 2400;
        var lines = new List<string>();
        foreach (var rawLine in body.Split(['\r', '\n']))
        {
            var trimmed = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                if (lines.Count > 0 && lines[^1].Length > 0)
                {
                    lines.Add(string.Empty);
                }

                continue;
            }

            if (trimmed.StartsWith("---", StringComparison.Ordinal) ||
                trimmed.StartsWith("***", StringComparison.Ordinal))
            {
                continue;
            }

            string formatted;
            if (trimmed.StartsWith('#'))
            {
                formatted = trimmed.TrimStart('#').Trim();
            }
            else if (trimmed.StartsWith("- ", StringComparison.Ordinal) ||
                     trimmed.StartsWith("* ", StringComparison.Ordinal))
            {
                formatted = "• " + trimmed[2..].Trim();
            }
            else if (trimmed.StartsWith("> ", StringComparison.Ordinal))
            {
                formatted = trimmed[2..].Trim();
            }
            else
            {
                formatted = trimmed;
            }

            formatted = formatted.Replace("**", string.Empty, StringComparison.Ordinal)
                                 .Replace("__", string.Empty, StringComparison.Ordinal)
                                 .Replace("`", string.Empty, StringComparison.Ordinal);
            if (!string.IsNullOrWhiteSpace(formatted))
            {
                lines.Add(formatted);
            }
        }

        while (lines.Count > 0 && lines[^1].Length == 0)
        {
            lines.RemoveAt(lines.Count - 1);
        }

        var joined = string.Join(Environment.NewLine, lines);
        return joined.Length <= maxLength
            ? joined
            : joined[..(maxLength - 3)].TrimEnd() + "...";
    }
}
