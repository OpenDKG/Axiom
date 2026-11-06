// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace Axiom.Contracts.Reputation;

public sealed record VirusTotalHashReport(
    bool Found,
    int Malicious,
    int Suspicious,
    int Undetected,
    int Harmless,
    string? Name,
    string? Type,
    DateTimeOffset? LastAnalysisUtc)
{
    public string Summary => Found
        ? $"{Malicious} malicious, {Suspicious} suspicious, {Undetected} undetected, {Harmless} harmless"
        : "Hash not found by VirusTotal";
}

/// <summary>
/// Hash-only VirusTotal client. It sends only the SHA-256, never a file, path or URL. The caller
/// must opt in and supply the user's own API key.
/// </summary>
public sealed class VirusTotalClient : IDisposable
{
    private static readonly Uri BaseUri = new("https://www.virustotal.com/api/v3/files/");

    private readonly HttpClient _http;

    private readonly bool _ownsHttpClient;

    public VirusTotalClient(HttpClient? httpClient = null)
    {
        _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        _ownsHttpClient = httpClient is null;
    }

    public async Task<VirusTotalHashReport> LookupHashAsync(
        string sha256,
        string apiKey,
        CancellationToken cancellationToken)
    {
        if (!IsSha256(sha256))
        {
            throw new ArgumentException("A 64-character SHA-256 hex string is required.", nameof(sha256));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(apiKey);

        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(BaseUri, sha256.ToUpperInvariant()));
        request.Headers.TryAddWithoutValidation("x-apikey", apiKey.Trim());

        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new VirusTotalHashReport(false, 0, 0, 0, 0, null, null, null);
        }

        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        using var document = JsonDocument.Parse(body);
        var attributes = document.RootElement
            .GetProperty("data")
            .GetProperty("attributes");
        var stats = attributes.GetProperty("last_analysis_stats");

        var lastAnalysis = attributes.TryGetProperty("last_analysis_date", out var lastDate) &&
            lastDate.TryGetInt64(out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : (DateTimeOffset?)null;

        return new VirusTotalHashReport(
            true,
            ReadInt(stats, "malicious"),
            ReadInt(stats, "suspicious"),
            ReadInt(stats, "undetected"),
            ReadInt(stats, "harmless"),
            attributes.TryGetProperty("meaningful_name", out var name) ? name.GetString() : null,
            attributes.TryGetProperty("type_description", out var type) ? type.GetString() : null,
            lastAnalysis);
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    private static int ReadInt(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.TryGetInt32(out var number)
            ? number
            : 0;
}
