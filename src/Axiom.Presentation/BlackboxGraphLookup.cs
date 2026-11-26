// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace Axiom.Presentation;

/// <summary>What the local Blackbox dashboard returned for one indicator.</summary>
public enum GraphLookupKind
{
    Public = 0,
    Local = 1,
    Community = 2,
    NotFound = 3,
    Unknown = 4,
}

/// <summary>
/// One user-triggered, read-only answer from the local Blackbox graph. It is deliberately not a
/// badge and carries no "verified" claim: the caller shows the tier, sources and reporter count,
/// and treats missing provenance as unknown.
/// </summary>
public sealed record GraphLookupResult(
    GraphLookupKind Kind,
    string Identifier,
    string Tier,
    string Category,
    IReadOnlyList<string> Sources,
    int Reporters,
    string Note,
    DateTimeOffset LookedUpUtc)
{
    public bool HasEntry => Kind is GraphLookupKind.Public or GraphLookupKind.Local or GraphLookupKind.Community;

    public string Describe()
    {
        var lines = new List<string>();
        switch (Kind)
        {
            case GraphLookupKind.Public:
                lines.Add("Public graph entry found.");
                break;
            case GraphLookupKind.Local:
                lines.Add("Local graph entry found (this node's synced data).");
                break;
            case GraphLookupKind.Community:
                lines.Add("Community graph entry found. A community sighting is not a verified verdict.");
                break;
            case GraphLookupKind.NotFound:
                lines.Add("No entry found in the public, local or community graph.");
                lines.Add("Unknown, not clean: absence from the graph does not prove the indicator is safe.");
                break;
            default:
                lines.Add("The local Blackbox dashboard did not answer or returned an unreadable result.");
                lines.Add("Unknown, not clean.");
                break;
        }

        lines.Add($"Identifier: {Identifier}");
        if (Tier.Length > 0)
        {
            lines.Add($"Tier: {Tier}");
        }

        if (Category.Length > 0)
        {
            lines.Add($"Category: {Category}");
        }

        if (Sources.Count > 0)
        {
            lines.Add("Sources: " + string.Join(", ", Sources));
        }

        lines.Add($"Reporters: {Reporters}");
        if (Note.Length > 0)
        {
            lines.Add(Note);
        }

        lines.Add($"Looked up {LookedUpUtc.ToLocalTime():HH:mm:ss}.");
        return string.Join("\n", lines);
    }
}

/// <summary>
/// Read-only per-indicator lookup against the local Blackbox dashboard (<c>/api/threat</c>).
/// It is user-triggered, bounded (5s), cached for a few minutes and never called from the
/// per-connection path. It accepts loopback endpoints only and does not contact a DKG directly.
/// </summary>
public sealed class BlackboxGraphLookup : IDisposable
{
    public const string DefaultBaseUrl = "http://127.0.0.1:9700";

    public static readonly TimeSpan DefaultCacheTtl = TimeSpan.FromMinutes(10);

    private const int DefaultCacheEntries = 256;

    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(5);

    private static readonly string[] Tiers = ["public", "local", "community"];

    private readonly HttpClient _http;

    private readonly bool _ownsHttpClient;

    private readonly Uri? _baseUri;

    private readonly TimeSpan _cacheTtl;

    private readonly int _cacheEntries;

    private readonly Func<DateTimeOffset> _clock;

    private readonly Dictionary<string, (DateTimeOffset ExpiresUtc, GraphLookupResult Result)> _cache =
        new(StringComparer.Ordinal);

    private readonly object _cacheGate = new();

    public BlackboxGraphLookup(
        HttpClient? httpClient = null,
        string? baseUrl = null,
        TimeSpan? cacheTtl = null,
        int cacheEntries = DefaultCacheEntries,
        Func<DateTimeOffset>? clock = null)
    {
        _http = httpClient ?? new HttpClient { Timeout = QueryTimeout };
        _ownsHttpClient = httpClient is null;
        _baseUri = TryCreateLoopbackBaseUri(baseUrl, out var uri) ? uri : null;
        _cacheTtl = cacheTtl ?? DefaultCacheTtl;
        _cacheEntries = Math.Clamp(cacheEntries, 1, 2_048);
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    public async Task<GraphLookupResult> LookupDomainAsync(
        string? domain,
        CancellationToken cancellationToken = default)
    {
        var normalized = (domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        if (normalized.Length == 0)
        {
            return Unknown("ioc:domain:", "The domain is empty.");
        }

        return await LookupAsync("ioc:domain:" + normalized, cancellationToken).ConfigureAwait(false);
    }

    public async Task<GraphLookupResult> LookupAsync(
        string? identifier,
        CancellationToken cancellationToken = default)
    {
        var id = (identifier ?? string.Empty).Trim();
        if (id.Length == 0)
        {
            return Unknown(id, "The identifier is empty.");
        }

        var now = _clock();
        if (TryGetCached(id, now, out var cached))
        {
            return cached;
        }

        if (_baseUri is null)
        {
            return Unknown(id, "The local Blackbox endpoint is not a loopback HTTP URL.");
        }

        foreach (var tier in Tiers)
        {
            var result = await QueryTierAsync(id, tier, cancellationToken).ConfigureAwait(false);
            if (result.Kind == GraphLookupKind.Unknown)
            {
                return result;
            }

            if (result.Kind != GraphLookupKind.NotFound)
            {
                Cache(id, result, now);
                return result;
            }
        }

        var notFound = new GraphLookupResult(
            GraphLookupKind.NotFound,
            id,
            string.Empty,
            string.Empty,
            [],
            0,
            string.Empty,
            _clock());
        Cache(id, notFound, now);
        return notFound;
    }

    private async Task<GraphLookupResult> QueryTierAsync(
        string identifier,
        string tier,
        CancellationToken cancellationToken)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(QueryTimeout);

            var uri = new Uri(
                _baseUri!,
                $"api/threat?tier={tier}&identifier={Uri.EscapeDataString(identifier)}");
            using var response = await _http
                .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, timeout.Token)
                .ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return Unknown(identifier, $"The dashboard answered HTTP {(int)response.StatusCode}.");
            }

            var body = await ReadBoundedAsync(response, timeout.Token).ConfigureAwait(false);
            if (body is null)
            {
                return Unknown(identifier, "The dashboard response exceeded the size limit.");
            }
            return Parse(identifier, tier, body);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Unknown(identifier, "The dashboard lookup timed out.");
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or JsonException)
        {
            return Unknown(identifier, "The dashboard lookup failed: " + exception.Message);
        }
    }

    private const int MaxResponseBytes = 2 * 1024 * 1024;

    private static async Task<string?> ReadBoundedAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        await using var stream = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxResponseBytes)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private GraphLookupResult Parse(string identifier, string requestedTier, string body)
    {
        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("found", out var found) ||
            found.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            return Unknown(identifier, "The dashboard did not return a recognized graph result.");
        }

        if (!found.GetBoolean())
        {
            return new GraphLookupResult(
                GraphLookupKind.NotFound,
                identifier,
                string.Empty,
                string.Empty,
                [],
                0,
                string.Empty,
                _clock());
        }

        var tier = ReadString(root, "tier");
        if (!Tiers.Contains(tier, StringComparer.OrdinalIgnoreCase))
        {
            tier = requestedTier;
        }

        var category = ReadString(root, "category");
        var sources = ReadSources(root);
        var reporters = ReadInt(root, "reporters");
        if (sources.Count == 0 && reporters == 0)
        {
            return Unknown(
                identifier,
                "An entry was found but no source or reporter provenance was returned; it is not treated as verified.");
        }

        var kind = tier.ToLowerInvariant() switch
        {
            "public" => GraphLookupKind.Public,
            "local" => GraphLookupKind.Local,
            "community" => GraphLookupKind.Community,
            _ => GraphLookupKind.Unknown,
        };
        return kind == GraphLookupKind.Unknown
            ? Unknown(identifier, "The dashboard returned an unrecognized tier.")
            : new GraphLookupResult(
                kind,
                identifier,
                tier,
                category,
                sources,
                reporters,
                string.Empty,
                _clock());
    }

    private bool TryGetCached(string identifier, DateTimeOffset now, out GraphLookupResult result)
    {
        lock (_cacheGate)
        {
            if (_cache.TryGetValue(identifier, out var entry) && entry.ExpiresUtc > now)
            {
                result = entry.Result;
                return true;
            }
        }

        result = null!;
        return false;
    }

    private void Cache(string identifier, GraphLookupResult result, DateTimeOffset now)
    {
        lock (_cacheGate)
        {
            if (_cache.Count >= _cacheEntries)
            {
                var expired = _cache
                    .Where(entry => entry.Value.ExpiresUtc <= now)
                    .Select(entry => entry.Key)
                    .ToArray();
                foreach (var key in expired)
                {
                    _cache.Remove(key);
                }

                if (_cache.Count >= _cacheEntries)
                {
                    _cache.Remove(_cache.Keys.First());
                }
            }

            _cache[identifier] = (now + _cacheTtl, result);
        }
    }

    private static GraphLookupResult Unknown(string identifier, string note) => new(
        GraphLookupKind.Unknown,
        identifier,
        string.Empty,
        string.Empty,
        [],
        0,
        note,
        DateTimeOffset.UtcNow);

    private static string ReadString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;

    private static int ReadInt(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.TryGetInt32(out var number) ? number : 0;

    private static List<string> ReadSources(JsonElement root)
    {
        var sources = new List<string>();
        if (!root.TryGetProperty("sources", out var array) || array.ValueKind != JsonValueKind.Array)
        {
            return sources;
        }

        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String && item.GetString() is { Length: > 0 } text)
            {
                sources.Add(text);
            }
            else if (item.ValueKind == JsonValueKind.Object)
            {
                var name = ReadString(item, "name");
                if (name.Length == 0)
                {
                    name = ReadString(item, "value");
                }

                if (name.Length == 0)
                {
                    name = ReadString(item, "identifier");
                }

                if (name.Length > 0)
                {
                    sources.Add(name);
                }
            }
        }

        return sources;
    }

    private static bool TryCreateLoopbackBaseUri(string? value, out Uri uri)
    {
        uri = null!;
        if (!Uri.TryCreate(value ?? DefaultBaseUrl, UriKind.Absolute, out var parsed) ||
            (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps) ||
            !parsed.IsLoopback)
        {
            return false;
        }

        uri = parsed;
        return true;
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
