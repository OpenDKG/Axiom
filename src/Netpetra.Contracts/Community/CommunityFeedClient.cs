// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Netpetra.Contracts.Community;

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

        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        using var document = JsonDocument.Parse(body);

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
