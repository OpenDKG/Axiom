// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Axiom.Contracts.Blackbox;

/// <summary>One identity probe against the local DKG node.</summary>
public sealed record DkgIdentity(
    bool Verified,
    int? StatusCode,
    string Home,
    string? AgentAddress,
    string? AgentDid,
    string Detail)
{
    /// <summary>A short line for install logs and the health strip.</summary>
    public string Summary => Verified
        ? $"DKG identity verified for {AgentAddress ?? "this node"} ({Home})"
        : $"DKG identity NOT verified: {Detail} ({Home})";
}

/// <summary>
/// Answers the one question #307 asks: does the running node accept the token from the home that
/// Axiom, the guard and the CLI resolve? A 401 here is exactly the token mismatch that silently
/// stops findings from reaching the local graph, so Setup and the health check report it instead
/// of showing "connected" for a node that rejects every write.
/// </summary>
public static class DkgIdentityProbe
{
    /// <summary>Port the DKG node used before it started writing <c>api.port</c>.</summary>
    public const int DefaultPort = 9200;

    private static readonly HttpClient SharedClient = new()
    {
        Timeout = TimeSpan.FromSeconds(5),
    };

    /// <summary>
    /// Reads the port and bearer token from <paramref name="home"/> and calls
    /// <c>GET /api/agent/identity</c>. The token is never logged or included in the result.
    /// </summary>
    public static async Task<DkgIdentity> CheckAsync(
        string home,
        HttpClient? client = null,
        CancellationToken cancellationToken = default)
    {
        var portFile = Path.Combine(home, "api.port");
        var tokenFile = Path.Combine(home, "auth.token");

        string tokenText;
        string portText;
        try
        {
            if (!File.Exists(tokenFile))
            {
                return NotVerified(home, "no auth.token in this DKG home");
            }

            tokenText = await File.ReadAllTextAsync(tokenFile, cancellationToken).ConfigureAwait(false);
            portText = File.Exists(portFile)
                ? await File.ReadAllTextAsync(portFile, cancellationToken).ConfigureAwait(false)
                : string.Empty;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return NotVerified(home, "the DKG home could not be read");
        }

        var token = DkgHomeResolver.ReadToken(tokenText);
        if (token is null)
        {
            return NotVerified(home, "auth.token has no token line");
        }

        var port = DkgHomeResolver.ReadApiPort(portText) ?? DefaultPort;
        var uri = new Uri($"http://127.0.0.1:{port}/api/agent/identity");

        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        try
        {
            using var response = await (client ?? SharedClient)
                .SendAsync(request, cancellationToken)
                .ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                return new DkgIdentity(
                    false,
                    401,
                    home,
                    null,
                    null,
                    "the running node rejected this home's token (401); node, guard and CLI are using different DKG homes");
            }

            if (!response.IsSuccessStatusCode)
            {
                return new DkgIdentity(
                    false,
                    (int)response.StatusCode,
                    home,
                    null,
                    null,
                    $"identity endpoint answered {(int)response.StatusCode}");
            }

            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return NotVerified(home, "identity endpoint returned no object");
            }

            var address = ReadString(root, "agentAddress");
            var did = ReadString(root, "agentDid");
            return string.IsNullOrWhiteSpace(address)
                ? NotVerified(home, "identity endpoint returned no agent address")
                : new DkgIdentity(true, 200, home, address, did, "identity endpoint accepted the token");
        }
        catch (Exception exception) when (
            exception is HttpRequestException or TaskCanceledException or JsonException)
        {
            return new DkgIdentity(
                false,
                null,
                home,
                null,
                null,
                $"the node did not answer on port {port}");
        }
    }

    private static DkgIdentity NotVerified(string home, string detail) =>
        new(false, null, home, null, null, detail);

    private static string? ReadString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
