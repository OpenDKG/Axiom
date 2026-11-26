// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Axiom.Contracts;

namespace Axiom.Presentation;

/// <summary>
/// Checks GitHub Releases on startup and at most once every 15 minutes when opted in, and exposes
/// whether a newer stable release is available. Installer downloads require an explicit user action.
/// </summary>
public sealed class UpdateCheckService : IDisposable
{
    public const string DefaultReleasesPageUrl = ProjectLinks.Releases;
    private const string RepositoryWebPrefix = DefaultReleasesPageUrl + "/tag/";
    private const string WindowsInstallerName = "Axiom-Setup.exe";
    private const long MaxInstallerBytes = 512L * 1024 * 1024;
    public static readonly TimeSpan MinimumCheckInterval = TimeSpan.FromMinutes(15);

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
    private InstallerAsset? _platformInstaller;
    private string? _lastEtag;
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

    public bool HasDirectInstaller => _platformInstaller is not null;

    private sealed record InstallerAsset(string FileName, Uri DownloadUri, long Size, string Sha256);

    /// <summary>Downloads the verified Windows installer for the detected release.</summary>
    public Task<string> DownloadWindowsInstallerAsync(
        CancellationToken cancellationToken,
        IProgress<int>? progress = null) =>
        DownloadPlatformInstallerAsync(cancellationToken, progress);

    /// <summary>Downloads the verified platform release package (Windows EXE, Ubuntu DEB, or macOS ZIP).</summary>
    public async Task<string> DownloadPlatformInstallerAsync(
        CancellationToken cancellationToken,
        IProgress<int>? progress = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var asset = _platformInstaller;
        if (!_isUpdateAvailable || asset is null)
        {
            throw new InvalidOperationException("This release does not provide a verifiable package for this platform.");
        }

        var safeFileName = Path.GetFileName(asset.FileName);
        if (string.IsNullOrWhiteSpace(safeFileName) ||
            !string.Equals(safeFileName, asset.FileName, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The release asset file name is invalid.");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(15));
        var token = timeout.Token;
        var settingsDirectory = Path.GetDirectoryName(Path.GetFullPath(_settingsStore.SettingsPath))!;
        var directory = Path.Combine(settingsDirectory, "updates");
        Directory.CreateDirectory(directory);
        var installerPath = Path.Combine(directory, safeFileName);
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
            if (!force && !string.IsNullOrWhiteSpace(_lastEtag))
            {
                request.Headers.TryAddWithoutValidation("If-None-Match", _lastEtag);
            }

            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken)
                .ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.NotModified)
            {
                _lastCheckSucceeded = true;
                return _isUpdateAvailable;
            }

            if (!response.IsSuccessStatusCode)
            {
                return false;
            }

            if (response.Headers.ETag?.Tag is { Length: > 0 } etag)
            {
                _lastEtag = etag;
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
        _platformInstaller = ReadPlatformInstaller(root, tagName!);
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
        _platformInstaller = null;
        _lastEtag = null;
        if (changed)
        {
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }

    internal static bool IsMatchingPlatformAsset(
        string? assetName,
        bool isWindows,
        bool isLinux,
        bool isMacOS)
    {
        if (string.IsNullOrWhiteSpace(assetName))
        {
            return false;
        }

        if (isWindows)
        {
            return string.Equals(assetName, WindowsInstallerName, StringComparison.Ordinal);
        }

        if (isLinux)
        {
            return assetName.StartsWith("axiom-firewall_", StringComparison.Ordinal) &&
                   assetName.EndsWith("_amd64.deb", StringComparison.Ordinal);
        }

        if (isMacOS)
        {
            return assetName.StartsWith("Axiom-", StringComparison.Ordinal) &&
                   assetName.EndsWith("-osx-x64-adhoc.zip", StringComparison.Ordinal);
        }

        return false;
    }

    private static InstallerAsset? ReadPlatformInstaller(JsonElement release, string tag)
    {
        if (!release.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var asset in assets.EnumerateArray())
        {
            if (asset.ValueKind != JsonValueKind.Object ||
                !asset.TryGetProperty("name", out var nameProp) ||
                nameProp.ValueKind != JsonValueKind.String ||
                nameProp.GetString() is not { } assetName ||
                !IsMatchingPlatformAsset(
                    assetName,
                    OperatingSystem.IsWindows(),
                    OperatingSystem.IsLinux(),
                    OperatingSystem.IsMacOS()))
            {
                continue;
            }

            var downloadUri = new Uri(
                $"{DefaultReleasesPageUrl}/download/{Uri.EscapeDataString(tag)}/{Uri.EscapeDataString(assetName)}");
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

            return new InstallerAsset(assetName, downloadUri, size, digestText[7..]);
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

        const int maxBullets = 6;
        const int maxBulletLength = 190;
        const int maxTotalLength = 1600;
        var items = new List<string>();
        var bulletCount = 0;

        foreach (var rawLine in body.Split(['\r', '\n']))
        {
            var isIndented = rawLine.StartsWith("  ", StringComparison.Ordinal) ||
                             rawLine.StartsWith('\t');
            var trimmed = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                continue;
            }

            if (trimmed.StartsWith("---", StringComparison.Ordinal) ||
                trimmed.StartsWith("***", StringComparison.Ordinal))
            {
                continue;
            }

            var isBullet = trimmed.StartsWith("- ", StringComparison.Ordinal) ||
                           trimmed.StartsWith("* ", StringComparison.Ordinal);
            if (isIndented && isBullet)
            {
                continue;
            }

            if (trimmed.StartsWith('#'))
            {
                var heading = StripIssueRefs(StripMarkdownLinks(trimmed.TrimStart('#').Trim())).Trim();
                if (heading.StartsWith("Downloads", StringComparison.OrdinalIgnoreCase) ||
                    heading.StartsWith("Assets", StringComparison.OrdinalIgnoreCase) ||
                    heading.StartsWith("Checksums", StringComparison.OrdinalIgnoreCase) ||
                    heading.StartsWith("SHA-256", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }

                if (items.Count == 0 &&
                    (heading.StartsWith("Axiom ", StringComparison.OrdinalIgnoreCase) ||
                     heading.Equals("What's New", StringComparison.OrdinalIgnoreCase) ||
                     heading.Equals("Highlights", StringComparison.OrdinalIgnoreCase) ||
                     heading.Equals("Release Notes", StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(heading))
                {
                    items.Add(heading);
                }

                continue;
            }

            var text = isBullet
                ? trimmed[2..].Trim()
                : trimmed.StartsWith("> ", StringComparison.Ordinal)
                    ? trimmed[2..].Trim()
                    : trimmed;

            text = text.Replace("**", string.Empty, StringComparison.Ordinal)
                       .Replace("__", string.Empty, StringComparison.Ordinal)
                       .Replace("`", string.Empty, StringComparison.Ordinal);
            text = StripMarkdownLinks(text);
            text = StripIssueRefs(text);
            if (isBullet && text.EndsWith(':'))
            {
                text = text[..^1].TrimEnd();
            }

            if (string.IsNullOrWhiteSpace(text))
            {
                continue;
            }

            if (isBullet)
            {
                if (bulletCount >= maxBullets)
                {
                    continue;
                }

                text = ShortenBullet(text, maxBulletLength);
                items.Add("• " + text);
                bulletCount++;
            }
            else
            {
                items.Add(ShortenBullet(text, maxBulletLength));
            }
        }

        if (items.Count == 0)
        {
            return string.Empty;
        }

        var separator = items.Any(item => item.Length > 85)
            ? Environment.NewLine + Environment.NewLine
            : Environment.NewLine;
        var joined = string.Join(separator, items);
        return joined.Length <= maxTotalLength
            ? joined
            : joined[..(maxTotalLength - 1)].TrimEnd() + "…";
    }

    private static string ShortenBullet(string text, int maxLength)
    {
        if (text.Length <= maxLength)
        {
            return text;
        }

        var sentenceEnd = text.IndexOf(". ", 50, StringComparison.Ordinal);
        if (sentenceEnd >= 50 && sentenceEnd < maxLength)
        {
            return text[..(sentenceEnd + 1)];
        }

        var cut = text.LastIndexOf(' ', maxLength - 1);
        return (cut > 40 ? text[..cut] : text[..(maxLength - 1)]).TrimEnd(' ', ',', ';') + "…";
    }

    private static string StripMarkdownLinks(string text)
    {
        if (!text.Contains('[', StringComparison.Ordinal))
        {
            return text;
        }

        var sb = new System.Text.StringBuilder(text.Length);
        var i = 0;
        while (i < text.Length)
        {
            if (text[i] == '[')
            {
                var closeBracket = text.IndexOf("](", i + 1, StringComparison.Ordinal);
                if (closeBracket > i + 1)
                {
                    var closeParen = text.IndexOf(')', closeBracket + 2);
                    if (closeParen > closeBracket + 2)
                    {
                        sb.Append(text, i + 1, closeBracket - i - 1);
                        i = closeParen + 1;
                        continue;
                    }
                }
            }

            sb.Append(text[i]);
            i++;
        }

        return sb.ToString();
    }

    private static string StripIssueRefs(string text)
    {
        var result = text;
        while (true)
        {
            var start = result.IndexOf(" (#", StringComparison.Ordinal);
            if (start < 0)
            {
                break;
            }

            var end = result.IndexOf(')', start + 3);
            if (end < 0)
            {
                break;
            }

            var validRef = true;
            for (var k = start + 2; k < end; k++)
            {
                var c = result[k];
                if (!char.IsAsciiDigit(c) && c != '#' && c != ',' && c != ' ')
                {
                    validRef = false;
                    break;
                }
            }

            if (!validRef)
            {
                break;
            }

            result = string.Concat(result.AsSpan(0, start), result.AsSpan(end + 1));
        }

        return result.Trim();
    }
}
