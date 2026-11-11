// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Http;
using System.Text.Json;

namespace Axiom.Contracts.Modules;

/// <summary>Read-only status of one optional local module.</summary>
public sealed record OptionalModuleStatus
{
    public required string Status { get; init; }

    public required string Detail { get; init; }

    public required bool IsConnected { get; init; }

    public string? Endpoint { get; init; }
}

/// <summary>
/// Probes optional modules that the user runs separately. Only loopback endpoints are accepted;
/// the probe never installs, starts, stops or controls a module and never sends data off the host.
/// </summary>
public sealed class OptionalModuleProbe : IDisposable
{
    public const string DefaultDkgUrl = "http://127.0.0.1:9200";

    public const string DefaultBlackboxUrl = "http://127.0.0.1:9700";

    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(2);

    private readonly HttpClient _http;

    private readonly string _dkgUrl;

    private readonly string _blackboxUrl;

    private readonly bool _ownsHttpClient;

    public OptionalModuleProbe(
        HttpClient? httpClient = null,
        string? dkgUrl = null,
        string? blackboxUrl = null)
    {
        _http = httpClient ?? new HttpClient { Timeout = DefaultTimeout };
        _ownsHttpClient = httpClient is null;
        _dkgUrl = dkgUrl
                  ?? Environment.GetEnvironmentVariable("AXIOM_DKG_URL")
                  ?? Environment.GetEnvironmentVariable(LegacyIdentity.ProductName + "_DKG_URL")
                  ?? DefaultDkgUrl;
        _blackboxUrl = blackboxUrl
                       ?? Environment.GetEnvironmentVariable("AXIOM_BLACKBOX_URL")
                       ?? Environment.GetEnvironmentVariable(LegacyIdentity.ProductName + "_BLACKBOX_URL")
                       ?? DefaultBlackboxUrl;
    }

    public async Task<OptionalModuleStatus> ProbeDkgAsync(CancellationToken cancellationToken)
    {
        if (!TryCreateLoopbackUri(_dkgUrl, out var baseUri, out var error))
        {
            return Unavailable(error);
        }

        try
        {
            using var response = await _http
                .GetAsync(new Uri(baseUri, "/api/status"), cancellationToken)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return NotRunning(
                    $"The DKG endpoint answered HTTP {(int)response.StatusCode}. Start the node and check its status.",
                    baseUri);
            }

            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            var detail = DescribeDkg(body) ?? "Local DKG node answered /api/status.";

            return new OptionalModuleStatus
            {
                Status = "CONNECTED",
                Detail = detail,
                IsConnected = true,
                Endpoint = baseUri.ToString(),
            };
        }
        catch (HttpRequestException)
        {
            return NotRunning("No local DKG node answered. Start it with `dkg start`; setup is in docs/INTEGRATIONS.md. Axiom does not start it.", baseUri);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return NotRunning("The DKG status check timed out. Start it with `dkg start`; setup is in docs/INTEGRATIONS.md.", baseUri);
        }
    }

    public async Task<OptionalModuleStatus> ProbeBlackboxAsync(CancellationToken cancellationToken)
    {
        if (!TryCreateLoopbackUri(_blackboxUrl, out var baseUri, out var error))
        {
            return Unavailable(error);
        }

        try
        {
            using var response = await _http
                .GetAsync(new Uri(baseUri, "/api/graph-status"), cancellationToken)
                .ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                return new OptionalModuleStatus
                {
                    Status = "CONNECTED",
                    Detail = "Local Blackbox dashboard answered /api/graph-status.",
                    IsConnected = true,
                    Endpoint = baseUri.ToString(),
                };
            }

            return new OptionalModuleStatus
            {
                Status = "CONNECTED",
                Detail = $"Local Blackbox dashboard answered HTTP {(int)response.StatusCode}; graph status is not exposed.",
                IsConnected = true,
                Endpoint = baseUri.ToString(),
            };
        }
        catch (HttpRequestException)
        {
            return NotRunning("No local Blackbox dashboard answered. Start Blackbox separately; setup is in docs/INTEGRATIONS.md. Axiom does not start it.", baseUri);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return NotRunning("The Blackbox status check timed out. Start Blackbox separately; setup is in docs/INTEGRATIONS.md.", baseUri);
        }
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }

    private static OptionalModuleStatus NotRunning(string detail, Uri endpoint) => new()
    {
        Status = "NOT RUNNING",
        Detail = detail,
        IsConnected = false,
        Endpoint = endpoint.ToString(),
    };

    private static OptionalModuleStatus Unavailable(string detail) => new()
    {
        Status = "UNAVAILABLE",
        Detail = detail,
        IsConnected = false,
    };

    private static bool TryCreateLoopbackUri(string value, out Uri uri, out string error)
    {
        uri = null!;
        error = string.Empty;

        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed) ||
            (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps))
        {
            error = "The module endpoint is not a valid HTTP URL.";
            return false;
        }

        if (!parsed.IsLoopback)
        {
            error = "Only loopback endpoints are allowed; Axiom does not contact remote module services.";
            return false;
        }

        uri = parsed;
        return true;
    }

    private static string? DescribeDkg(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            var parts = new List<string>();

            AddIfPresent(root, "version", "version", parts);
            AddIfPresent(root, "peerId", "peer", parts);
            AddIfPresent(root, "nodeRole", "role", parts);
            AddIfPresent(root, "networkName", "network", parts);
            AddIfPresent(root, "networkId", "network id", parts);

            return parts.Count == 0 ? null : $"Local DKG node: {string.Join(", ", parts)}.";
        }
        catch (JsonException)
        {
            return "Local DKG node answered /api/status with unreadable JSON.";
        }
    }

    private static void AddIfPresent(
        JsonElement root,
        string propertyName,
        string label,
        List<string> parts)
    {
        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty(propertyName, out var value) &&
            value.ValueKind is JsonValueKind.String or JsonValueKind.Number)
        {
            parts.Add($"{label} {value}");
        }
    }
}
