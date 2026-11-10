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

/// <summary>
/// Fetches a user-configured HTTPS JSON feed. The feed is evidence, not a verdict; invalid entries
/// are ignored. No file, path or local connection data is sent.
/// </summary>
public sealed class CommunityFeedClient : IDisposable
{
    public const int MaxEntries = 1000;

    private const int MaxResponseBytes = 2 * 1024 * 1024;

    private readonly HttpClient _http;

    private readonly bool _ownsHttpClient;

    public CommunityFeedClient(HttpClient? httpClient = null)
    {
        _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        _ownsHttpClient = httpClient is null;
    }

    public async Task<CommunityFeedResult> FetchAsync(
        string url,
        string? token,
        CancellationToken cancellationToken)
    {
        string body;

        if (string.Equals(url, "axiom://starter", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(url, LegacyIdentity.StarterFeedUrl, StringComparison.OrdinalIgnoreCase))
        {
            var starter = Path.Combine(AppContext.BaseDirectory, "community", "feed.json");
            if (!File.Exists(starter))
            {
                throw new FileNotFoundException("Bundled starter community feed is missing.", starter);
            }

            body = await File.ReadAllTextAsync(starter, cancellationToken).ConfigureAwait(false);
            return Parse(body);
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("Community feed URL must be an absolute HTTPS URL.", nameof(url));
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

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
        return Parse(body);
    }

    private static CommunityFeedResult Parse(string body)
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

        return new CommunityFeedResult(parsed, DateTimeOffset.UtcNow);
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
