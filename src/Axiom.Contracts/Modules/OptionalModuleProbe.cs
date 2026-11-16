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

    /// <summary>Owning-process evidence, when the host can inspect it.</summary>
    public ModuleEndpointIdentity? Identity { get; init; }

    /// <summary>
    /// True only when the documented contract and the owning process were both observed. Any future
    /// privileged settings write must require this flag; an open port or a schema match is not enough.
    /// </summary>
    public bool CanReceivePrivilegedSettings =>
        IsConnected && Identity?.Level == ModuleEndpointIdentityLevel.ProcessObserved;
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

    private readonly ILoopbackListenerInspector? _listenerInspector;

    /// <summary>
    /// Creates an HTTP client configured for fast loopback-only requests so Windows auto-proxy
    /// (WPAD) detection cannot stall localhost health probes past their short timeout.
    /// </summary>
    public static HttpClient CreateLoopbackHttpClient(TimeSpan timeout)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(1),
        };
        return new HttpClient(handler, disposeHandler: true) { Timeout = timeout };
    }

    public OptionalModuleProbe(
        HttpClient? httpClient = null,
        string? dkgUrl = null,
        string? blackboxUrl = null,
        ILoopbackListenerInspector? listenerInspector = null)
    {
        _http = httpClient ?? CreateLoopbackHttpClient(DefaultTimeout);
        _ownsHttpClient = httpClient is null;
        _listenerInspector = listenerInspector;
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

        var primary = await ProbeDkgAtAsync(baseUri, fromBlackbox: false, cancellationToken)
            .ConfigureAwait(false);
        if (primary.IsConnected || primary.Status != "NOT RUNNING")
        {
            return primary;
        }

        // Blackbox runs its own DKG node. When Axiom has no standalone node, point the DKG card
        // at the node Blackbox reports instead of showing a false "not installed".
        if (await TryResolveBlackboxDkgAsync(cancellationToken).ConfigureAwait(false) is { } fallback)
        {
            var result = await ProbeDkgAtAsync(fallback, fromBlackbox: true, cancellationToken)
                .ConfigureAwait(false);
            if (result.IsConnected)
            {
                return result;
            }
        }

        return primary;
    }

    private async Task<OptionalModuleStatus> ProbeDkgAtAsync(
        Uri baseUri,
        bool fromBlackbox,
        CancellationToken cancellationToken)
    {
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
            if (!TryDescribeDkg(body, out var identity, out var problem))
            {
                return Unknown(problem, baseUri);
            }

            var endpointIdentity = VerifyIdentity(baseUri, dkg: true);
            if (endpointIdentity.Level == ModuleEndpointIdentityLevel.ProcessMismatch)
            {
                return Unknown(
                    $"Port {baseUri.Port} answered the DKG contract but is owned by {endpointIdentity.Detail}; " +
                    "it is not treated as the local node.",
                    baseUri) with { Identity = endpointIdentity };
            }

            return new OptionalModuleStatus
            {
                Status = "CONNECTED",
                Detail = $"{(fromBlackbox ? "DKG node reported by Blackbox" : "Local DKG node")}: {identity}. " +
                         IdentitySentence(endpointIdentity),
                IsConnected = true,
                Endpoint = baseUri.ToString(),
                Identity = endpointIdentity,
            };
        }
        catch (HttpRequestException)
        {
            return NotRunning("No local DKG node answered. Start it with the Start button in Axiom or `dkg start`; setup is in docs/INTEGRATIONS.md.", baseUri);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return NotRunning("The DKG status check timed out. Start it with the Start button in Axiom or `dkg start`; setup is in docs/INTEGRATIONS.md.", baseUri);
        }
    }

    private async Task<Uri?> TryResolveBlackboxDkgAsync(CancellationToken cancellationToken)
    {
        if (!TryCreateLoopbackUri(_blackboxUrl, out var blackboxUri, out _))
        {
            return null;
        }

        try
        {
            using var response = await _http
                .GetAsync(new Uri(blackboxUri, "/api/graph-status"), cancellationToken)
                .ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("node_reachable", out var reachable) ||
                reachable.ValueKind != JsonValueKind.True ||
                !root.TryGetProperty("dkg_url", out var dkgUrl) ||
                dkgUrl.ValueKind != JsonValueKind.String)
            {
                return null;
            }

            return TryCreateLoopbackUri(dkgUrl.GetString() ?? string.Empty, out var uri, out _)
                ? uri
                : null;
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException)
        {
            return null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
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

            if (!response.IsSuccessStatusCode)
            {
                return Unknown(
                    $"Something answered on the Blackbox port with HTTP {(int)response.StatusCode}; " +
                    "it did not return Blackbox graph status, so it is not treated as the dashboard.",
                    baseUri);
            }

            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!TryDescribeBlackbox(body, out var detail, out var problem))
            {
                return Unknown(problem, baseUri);
            }

            var endpointIdentity = VerifyIdentity(baseUri, dkg: false);
            if (endpointIdentity.Level == ModuleEndpointIdentityLevel.ProcessMismatch)
            {
                return Unknown(
                    $"Port {baseUri.Port} answered the Blackbox contract but is owned by {endpointIdentity.Detail}; " +
                    "it is not treated as the dashboard.",
                    baseUri) with { Identity = endpointIdentity };
            }

            return new OptionalModuleStatus
            {
                Status = "CONNECTED",
                Detail = $"{detail} {IdentitySentence(endpointIdentity)}",
                IsConnected = true,
                Endpoint = baseUri.ToString(),
                Identity = endpointIdentity,
            };
        }
        catch (HttpRequestException)
        {
            return NotRunning("No local Blackbox dashboard answered. Start it with the Start button in Axiom or its own launcher; setup is in docs/INTEGRATIONS.md.", baseUri);
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

    /// <summary>
    /// Ties the listener to the module runtime where the host can see it. A mismatched owner turns a
    /// schema-valid port into UNKNOWN; an unreadable owner keeps the schema result but never grants
    /// the endpoint privileged settings.
    /// </summary>
    private ModuleEndpointIdentity VerifyIdentity(Uri endpoint, bool dkg)
    {
        if (_listenerInspector is null)
        {
            return new ModuleEndpointIdentity
            {
                Level = ModuleEndpointIdentityLevel.Unverified,
                Detail = "owning process not inspected on this host",
            };
        }

        ModuleListenerOwner? owner;
        try
        {
            owner = _listenerInspector.FindOwner(endpoint);
        }
        catch (Exception exception) when (exception is
                     InvalidOperationException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            return new ModuleEndpointIdentity
            {
                Level = ModuleEndpointIdentityLevel.Unverified,
                Detail = "owning process could not be read",
            };
        }

        if (owner is null || string.IsNullOrWhiteSpace(owner.ProcessName))
        {
            return new ModuleEndpointIdentity
            {
                Level = ModuleEndpointIdentityLevel.Unverified,
                Detail = "listening process not resolved",
            };
        }

        var runtime = dkg ? IsDkgRuntime(owner.ProcessName) : IsBlackboxRuntime(owner.ProcessName);
        if (!runtime)
        {
            return new ModuleEndpointIdentity
            {
                Level = ModuleEndpointIdentityLevel.ProcessMismatch,
                Detail = $"process {owner.ProcessName} (PID {owner.ProcessId})",
                ProcessId = owner.ProcessId,
                ProcessName = owner.ProcessName,
            };
        }

        var evidence = $"{owner.ExecutablePath} {owner.CommandLine}";
        var token = dkg ? "dkg" : "blackbox";
        var named = evidence.Contains(token, StringComparison.OrdinalIgnoreCase);

        return new ModuleEndpointIdentity
        {
            Level = named ? ModuleEndpointIdentityLevel.ProcessObserved : ModuleEndpointIdentityLevel.Unverified,
            Detail = named
                ? $"process {owner.ProcessName} (PID {owner.ProcessId}) names {token}"
                : $"process {owner.ProcessName} (PID {owner.ProcessId}) without {token} evidence",
            ProcessId = owner.ProcessId,
            ProcessName = owner.ProcessName,
        };
    }

    private static bool IsDkgRuntime(string processName) =>
        RuntimeName(processName).Equals("node", StringComparison.OrdinalIgnoreCase)
        || RuntimeName(processName).Equals("dkg", StringComparison.OrdinalIgnoreCase);

    private static bool IsBlackboxRuntime(string processName) =>
        RuntimeName(processName).Equals("node", StringComparison.OrdinalIgnoreCase)
        || RuntimeName(processName).Equals("blackbox", StringComparison.OrdinalIgnoreCase)
        || RuntimeName(processName).Equals("hermes", StringComparison.OrdinalIgnoreCase)
        || RuntimeName(processName).StartsWith("python", StringComparison.OrdinalIgnoreCase);

    /// <summary>Windows reports "node.exe"; the runtime match must not depend on the suffix.</summary>
    private static string RuntimeName(string processName) =>
        processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? processName[..^4]
            : processName;

    private static string IdentitySentence(ModuleEndpointIdentity identity) => identity.Level switch
    {
        ModuleEndpointIdentityLevel.ProcessObserved => $"Owning {identity.Detail}.",
        ModuleEndpointIdentityLevel.Unverified => $"Owning process unverified ({identity.Detail}).",
        _ => $"Owning process mismatch ({identity.Detail}).",
    };

    private static OptionalModuleStatus NotRunning(string detail, Uri endpoint) => new()
    {
        Status = "NOT RUNNING",
        Detail = detail,
        IsConnected = false,
        Endpoint = endpoint.ToString(),
    };

    /// <summary>Something answered on the port but its response is not the module's documented shape.</summary>
    private static OptionalModuleStatus Unknown(string detail, Uri endpoint) => new()
    {
        Status = "UNKNOWN",
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

    private static readonly HashSet<string> KnownNetworkIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "7449c543ff04a550b2dafa999fe8ee577a00b212023bb4d4244e8d58a4792c7b", // DKG V10 Base Testnet
        "562ea760dbe27fb4233d58dfc958bbddf844b82596ec3d51dff98718e6bf61ca", // DKG V10 Base Mainnet
        "e08a9fb72a648ec2eb2fd9c152ded90a8ad67bb56f27df4781d9bb7e261fb7a7", // DKG V10 Gnosis Mainnet
        "83698bd2a305d6261169bfe96dd7c2f8aa9d24bee92150eee949a9a89bb68729", // DKG V10 NeuroWeb Mainnet
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

    private static bool TryDescribeDkg(string json, out string detail, out string problem)
    {
        detail = string.Empty;
        problem = "Something answered on the DKG port but did not return /api/status; it is not treated as a DKG node.";

        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            var version = ReadString(root, "version");
            var peerId = ReadString(root, "peerId");
            var role = ReadString(root, "nodeRole");
            var networkId = ReadString(root, "networkId");
            if (version.Length == 0 ||
                role.Length == 0 ||
                networkId.Length == 0 ||
                !peerId.StartsWith("12D3Koo", StringComparison.Ordinal))
            {
                problem = "The listener on the DKG port did not provide the documented /api/status " +
                          "identity fields (version, peerId, nodeRole, networkId); it is not treated as a DKG node.";
                return false;
            }

            if (!KnownNetworkIds.Contains(networkId))
            {
                problem = $"A DKG-like node answered with unrecognized network id {networkId}; " +
                          "Axiom accepts only the known testnet and mainnet ids.";
                return false;
            }

            var networkName = ReadString(root, "networkName");
            detail = $"version {version}, peer {peerId}, role {role}" +
                     (networkName.Length == 0 ? string.Empty : $", network {networkName}") +
                     $", network id {networkId[..8]}...";
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryDescribeBlackbox(string json, out string detail, out string problem)
    {
        detail = string.Empty;
        problem = "Something is listening on the Blackbox port but did not return Blackbox graph status; " +
                  "it is not treated as the dashboard.";

        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("mode", out var mode) ||
                mode.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("node_reachable", out var reachable) ||
                reachable.ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
                !root.TryGetProperty("dkg_url", out var dkgUrl) ||
                dkgUrl.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("sync_progress", out var syncProgress) ||
                syncProgress.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            detail = $"Blackbox dashboard: {mode.GetString()} mode, " +
                     $"DKG node {(reachable.GetBoolean() ? "reachable" : "offline")}.";
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string ReadString(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;
}
