// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Axiom.Contracts.Community;

public sealed record CommunityFeedEntry(
    string Sha256,
    string? Name,
    string? Verdict,
    string? Source,
    DateTimeOffset? UpdatedUtc);

public sealed record CommunityFeedResult(
    IReadOnlyList<CommunityFeedEntry> Entries,
    DateTimeOffset FetchedUtc);

public sealed record CommunityFeedPreset(
    string Id,
    string Name,
    string Url,
    string License,
    string Description)
{
    public override string ToString() => $"{Name} ({License})";
}

/// <summary>Catalog of license-cleared SHA-256 malware feeds for local folder scanning.</summary>
public static class CommunityFeedCatalog
{
    public const string RecommendedBundleUrl =
        "axiom://starter;" +
        "https://www.botvrij.eu/data/ioclist.sha256.raw;" +
        "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-ab.txt";

    public static IReadOnlyList<CommunityFeedPreset> Presets { get; } =
    [
        new(
            "recommended-bundle",
            "Recommended malware SHA-256 bundle (Starter + Botvrij + Malicious-Hash)",
            RecommendedBundleUrl,
            "CC0-1.0 / MIT / GPL-3.0",
            "Combines the offline EICAR test entry, Botvrij.eu OSINT malware SHA-256 IOCs, and Romain Marcoux malicious SHA-256 hashes."),
        new(
            "starter",
            "Axiom starter feed (bundled offline EICAR test)",
            "axiom://starter",
            "GPL-3.0",
            "Bundled offline test entry for verifying local SHA-256 matching without network access."),
        new(
            "botvrij-sha256",
            "Botvrij.eu OSINT malware SHA-256 IOCs",
            "https://www.botvrij.eu/data/ioclist.sha256.raw",
            "CC0-1.0",
            "Public-domain SHA-256 file indicators of malware samples curated by Botvrij.eu."),
        new(
            "malicious-hash-ab",
            "Romain Marcoux malicious SHA-256 hashes (MIT)",
            "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-ab.txt",
            "MIT",
            "Openly aggregated SHA-256 hashes of known malware binaries."),
    ];
}

/// <summary>
/// Fetches user-configured HTTPS JSON or plain-text SHA-256 feeds. The feed is evidence, not a
/// verdict; invalid entries are ignored. No file, path or local connection data is sent.
/// </summary>
public sealed class CommunityFeedClient : IDisposable
{
    public const int MaxEntries = 1000;

    private const int MaxResponseBytes = 4 * 1024 * 1024;

    private readonly HttpClient _http;

    private readonly bool _ownsHttpClient;

    public CommunityFeedClient(HttpClient? httpClient = null)
    {
        if (httpClient is null)
        {
            var handler = new SocketsHttpHandler
            {
                UseProxy = false,
                ConnectTimeout = TimeSpan.FromSeconds(5),
            };
            _http = new HttpClient(handler, disposeHandler: true)
            {
                Timeout = TimeSpan.FromSeconds(15),
            };
            _http.DefaultRequestHeaders.UserAgent.TryParseAdd("Axiom-CommunityFeed/0.1");
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttpClient = false;
        }
    }

    public async Task<CommunityFeedResult> FetchAsync(
        string url,
        string? token,
        CancellationToken cancellationToken)
    {
        var urls = SplitUrls(url);
        if (urls.Count == 0)
        {
            throw new ArgumentException("Community feed URL must not be empty.", nameof(url));
        }

        // Validate all feed URLs upfront before issuing any HTTP request.
        foreach (var singleUrl in urls)
        {
            if (!IsStarterUrl(singleUrl) &&
                (!Uri.TryCreate(singleUrl, UriKind.Absolute, out var validated) ||
                 validated.Scheme != Uri.UriSchemeHttps))
            {
                throw new ArgumentException("Community feed URL must be an absolute HTTPS URL.", nameof(url));
            }
        }

        var merged = new List<CommunityFeedEntry>();
        var seenHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var singleUrl in urls)
        {
            if (merged.Count >= MaxEntries)
            {
                break;
            }

            var partial = await FetchSingleAsync(singleUrl, token, cancellationToken).ConfigureAwait(false);
            foreach (var entry in partial)
            {
                if (!seenHashes.Add(entry.Sha256))
                {
                    continue;
                }

                merged.Add(entry);
                if (merged.Count >= MaxEntries)
                {
                    break;
                }
            }
        }

        return new CommunityFeedResult(merged, DateTimeOffset.UtcNow);
    }

    private async Task<List<CommunityFeedEntry>> FetchSingleAsync(
        string singleUrl,
        string? token,
        CancellationToken cancellationToken)
    {
        string body;
        string sourceLabel;

        if (IsStarterUrl(singleUrl))
        {
            var starter = Path.Combine(AppContext.BaseDirectory, "community", "feed.json");
            if (!File.Exists(starter))
            {
                throw new FileNotFoundException("Bundled starter community feed is missing.", starter);
            }

            body = await File.ReadAllTextAsync(starter, cancellationToken).ConfigureAwait(false);
            sourceLabel = "Axiom starter feed";
            return Parse(body, sourceLabel);
        }

        var uri = new Uri(singleUrl, UriKind.Absolute);
        sourceLabel = uri.Host;

        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/plain"));

        if (!string.IsNullOrWhiteSpace(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Trim());
        }

        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxResponseBytes)
            {
                throw new InvalidDataException(
                    $"The community feed exceeded the {MaxResponseBytes / (1024 * 1024)} MB limit.");
            }

            buffer.Write(chunk, 0, read);
        }

        body = Encoding.UTF8.GetString(buffer.ToArray());
        return Parse(body, sourceLabel);
    }

    private static List<string> SplitUrls(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return [];
        }

        return url
            .Split([';', ',', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(item => item.Trim())
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static bool IsStarterUrl(string url) =>
        string.Equals(url, "axiom://starter", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(url, LegacyIdentity.StarterFeedUrl, StringComparison.OrdinalIgnoreCase);

    private static List<CommunityFeedEntry> Parse(string body, string sourceLabel)
    {
        var trimmed = body.Trim();
        if (LooksLikeJson(trimmed))
        {
            return ParseJson(trimmed);
        }

        return ParsePlainText(trimmed, sourceLabel);
    }

    private static bool LooksLikeJson(string trimmed) =>
        trimmed.StartsWith('{') ||
        trimmed.StartsWith('[') ||
        trimmed.StartsWith('"') ||
        string.Equals(trimmed, "null", StringComparison.Ordinal);

    private static List<CommunityFeedEntry> ParseJson(string body)
    {
        using var document = JsonDocument.Parse(body);

        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("Community feed root must be a JSON object.");
        }

        if (!document.RootElement.TryGetProperty("entries", out var entries) ||
            entries.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("Community feed must contain an 'entries' array.");
        }

        var parsed = new List<CommunityFeedEntry>();
        foreach (var entry in entries.EnumerateArray())
        {
            if (parsed.Count >= MaxEntries)
            {
                break;
            }

            if (entry.ValueKind != JsonValueKind.Object ||
                !entry.TryGetProperty("sha256", out var hashElement) ||
                hashElement.ValueKind != JsonValueKind.String ||
                hashElement.GetString() is not { } hash ||
                !IsSha256(hash))
            {
                continue;
            }

            parsed.Add(new CommunityFeedEntry(
                hash.ToUpperInvariant(),
                ReadString(entry, "name"),
                ReadString(entry, "verdict"),
                ReadString(entry, "source"),
                ReadTimestamp(entry, "updatedUtc")));
        }

        return parsed;
    }

    private static List<CommunityFeedEntry> ParsePlainText(string body, string sourceLabel)
    {
        var parsed = new List<CommunityFeedEntry>();
        var now = DateTimeOffset.UtcNow;

        foreach (var rawLine in body.Split('\n'))
        {
            if (parsed.Count >= MaxEntries)
            {
                break;
            }

            var line = rawLine.Trim();
            if (string.IsNullOrEmpty(line) ||
                line.StartsWith('#') ||
                line.StartsWith(';') ||
                line.StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            var tokens = line.Split([' ', '\t', ',', ';'], StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length == 0)
            {
                continue;
            }

            var candidate = tokens[0].Trim().Trim('"');
            if (candidate.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
            {
                candidate = candidate[7..];
            }

            if (!IsSha256(candidate))
            {
                continue;
            }

            parsed.Add(new CommunityFeedEntry(
                candidate.ToUpperInvariant(),
                Name: null,
                Verdict: "malware",
                Source: sourceLabel,
                UpdatedUtc: now));
        }

        if (parsed.Count == 0)
        {
            throw new InvalidDataException("Community feed contained no valid SHA-256 hashes.");
        }

        return parsed;
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }

    private static string? ReadString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static DateTimeOffset? ReadTimestamp(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) &&
        value.ValueKind == JsonValueKind.String &&
        value.TryGetDateTimeOffset(out var timestamp)
            ? timestamp
            : null;

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');
}
