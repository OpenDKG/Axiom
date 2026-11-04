// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Netpetra.Contracts.Blackbox;

/// <summary>One audit row from Blackbox's local dashboard.</summary>
public sealed record BlackboxAuditEntry(
    DateTimeOffset? Timestamp,
    string Event,
    string Agent,
    string Session,
    string Tool,
    string Action,
    string Decision,
    string Severity,
    string Identifier,
    string Details)
{
    public string TimeText => Timestamp?.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture) ?? "—";

    public bool IsBlocked => string.Equals(Decision, "block", StringComparison.OrdinalIgnoreCase);

    public bool IsFlagged => string.Equals(Decision, "flag", StringComparison.OrdinalIgnoreCase);

    public bool IsThreat => IsBlocked || IsFlagged;
}

/// <summary>One finding from Blackbox's local findings API.</summary>
public sealed record BlackboxFinding(
    DateTimeOffset? Timestamp,
    string Identifier,
    string Category,
    string Severity,
    string Title,
    string Agent,
    string Session,
    string Tool,
    string Decision,
    string Source,
    bool Confirmed)
{
    public string TimeText => Timestamp?.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture) ?? "—";

    public bool IsBlocked => string.Equals(Decision, "block", StringComparison.OrdinalIgnoreCase);

    public bool IsFlagged => string.Equals(Decision, "flag", StringComparison.OrdinalIgnoreCase);
}

public sealed record BlackboxAuditPage(IReadOnlyList<BlackboxAuditEntry> Entries, int Total);

public sealed record BlackboxFindingPage(IReadOnlyList<BlackboxFinding> Findings, int Total);

public sealed record BlackboxSaveResult(bool Ok, IReadOnlyList<string> Errors, JsonObject? Settings);

/// <summary>
/// Read/write client for the local Blackbox dashboard. It is intentionally loopback-only and
/// never logs the session token or raw tool arguments.
/// </summary>
public sealed class BlackboxDashboardClient : IDisposable
{
    private const int MaxResponseBytes = 2 * 1024 * 1024;

    private readonly HttpClient _http;

    private readonly bool _ownsHttpClient;

    public BlackboxDashboardClient(HttpClient? httpClient = null, Uri? baseUri = null)
    {
        var uri = baseUri ?? new Uri("http://127.0.0.1:9700/");
        if (!uri.IsLoopback)
        {
            throw new ArgumentException("Blackbox dashboard must be a loopback address.", nameof(baseUri));
        }

        if (httpClient is null)
        {
            _http = new HttpClient { BaseAddress = uri, Timeout = TimeSpan.FromSeconds(6) };
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _http.BaseAddress ??= uri;
            _http.Timeout = TimeSpan.FromSeconds(6);
        }
    }

    public Task<JsonObject> GetSettingsAsync(CancellationToken cancellationToken) =>
        GetObjectAsync("api/settings", cancellationToken);

    public async Task<string> GetSessionTokenAsync(CancellationToken cancellationToken)
    {
        using var document = await GetJsonAsync("api/session", cancellationToken).ConfigureAwait(false);
        if (document.RootElement.TryGetProperty("token", out var token) &&
            token.ValueKind == JsonValueKind.String &&
            token.GetString() is { Length: > 0 } value)
        {
            return value;
        }

        throw new InvalidDataException("Blackbox session response did not contain a token.");
    }

    public async Task<BlackboxSaveResult> SaveSettingsAsync(
        JsonObject patch,
        CancellationToken cancellationToken)
    {
        var token = await GetSessionTokenAsync(cancellationToken).ConfigureAwait(false);
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/settings")
        {
            Content = new StringContent(
                patch.ToJsonString(),
                Encoding.UTF8,
                "application/json"),
        };
        request.Headers.Add("X-Blackbox-Token", token);

        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await ReadBoundedAsync(response, cancellationToken).ConfigureAwait(false);
        using var document = Parse(body);
        var root = document.RootElement;

        if (!response.IsSuccessStatusCode)
        {
            return new BlackboxSaveResult(false, ReadErrors(root), null);
        }

        if (root.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.False)
        {
            return new BlackboxSaveResult(false, ReadErrors(root), null);
        }

        var settings = await GetSettingsAsync(cancellationToken).ConfigureAwait(false);
        return new BlackboxSaveResult(true, [], settings);
    }

    public async Task<BlackboxAuditPage> GetAuditAsync(
        int limit,
        int offset,
        CancellationToken cancellationToken)
    {
        limit = Math.Clamp(limit, 1, 500);
        offset = Math.Max(0, offset);
        using var document = await GetJsonAsync(
            $"api/audit?limit={limit.ToString(CultureInfo.InvariantCulture)}&offset={offset.ToString(CultureInfo.InvariantCulture)}",
            cancellationToken).ConfigureAwait(false);

        var entries = new List<BlackboxAuditEntry>();
        if (document.RootElement.TryGetProperty("entries", out var array) &&
            array.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in array.EnumerateArray())
            {
                entries.Add(ParseAuditEntry(item));
            }
        }

        return new BlackboxAuditPage(entries, ReadInt(document.RootElement, "total"));
    }

    public async Task<BlackboxFindingPage> GetFindingsAsync(
        int limit,
        int offset,
        CancellationToken cancellationToken)
    {
        limit = Math.Clamp(limit, 1, 500);
        offset = Math.Max(0, offset);
        using var document = await GetJsonAsync(
            $"api/findings?limit={limit.ToString(CultureInfo.InvariantCulture)}&offset={offset.ToString(CultureInfo.InvariantCulture)}",
            cancellationToken).ConfigureAwait(false);

        var findings = new List<BlackboxFinding>();
        if (document.RootElement.TryGetProperty("findings", out var array) &&
            array.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in array.EnumerateArray())
            {
                findings.Add(ParseFinding(item));
            }
        }

        return new BlackboxFindingPage(findings, ReadInt(document.RootElement, "total"));
    }

    public Task<JsonObject> GetGraphStatusAsync(CancellationToken cancellationToken) =>
        GetObjectAsync("api/graph-status", cancellationToken);

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }

    private async Task<JsonObject> GetObjectAsync(string path, CancellationToken cancellationToken)
    {
        using var response = await _http.GetAsync(path, cancellationToken).ConfigureAwait(false);
        var body = await ReadBoundedAsync(response, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Blackbox {path} returned {(int)response.StatusCode}.");
        }

        try
        {
            return JsonNode.Parse(body) as JsonObject ??
                   throw new InvalidDataException($"Blackbox {path} response was not an object.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Blackbox {path} returned malformed JSON.", exception);
        }
    }

    private async Task<JsonDocument> GetJsonAsync(string path, CancellationToken cancellationToken)
    {
        using var response = await _http.GetAsync(path, cancellationToken).ConfigureAwait(false);
        var body = await ReadBoundedAsync(response, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Blackbox {path} returned {(int)response.StatusCode}.");
        }

        return Parse(body);
    }

    private static async Task<string> ReadBoundedAsync(
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
                throw new InvalidDataException("Blackbox response was larger than the allowed limit.");
            }

            buffer.Write(chunk, 0, read);
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static JsonDocument Parse(string body)
    {
        try
        {
            return JsonDocument.Parse(body);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Blackbox returned malformed JSON.", exception);
        }
    }

    private static string[] ReadErrors(JsonElement root)
    {
        if (!root.TryGetProperty("errors", out var errors) || errors.ValueKind != JsonValueKind.Array)
        {
            return ["Blackbox rejected the settings update."];
        }

        return errors.EnumerateArray()
            .Select(item => item.ValueKind == JsonValueKind.String ? item.GetString() ?? string.Empty : item.ToString())
            .Where(item => item.Length > 0)
            .ToArray();
    }

    private static BlackboxAuditEntry ParseAuditEntry(JsonElement root)
    {
        var detail = root.TryGetProperty("detail", out var detailElement) &&
                     detailElement.ValueKind == JsonValueKind.Object
            ? detailElement
            : default;

        var eventName = ReadString(root, "event") ?? "event";
        var agent = ReadString(root, "framework") ?? "Unknown";
        var session = ReadString(detail, "session_id") ?? string.Empty;
        var tool = ReadString(detail, "tool_name") ?? ReadString(root, "tool") ?? eventName;
        var decision = ReadString(detail, "decision")?.ToLowerInvariant() ?? "observed";
        if (detail.ValueKind == JsonValueKind.Object &&
            detail.TryGetProperty("blocked", out var blocked) &&
            blocked.ValueKind == JsonValueKind.Array &&
            blocked.GetArrayLength() > 0)
        {
            decision = "block";
        }

        var severity = (ReadString(root, "severity") ?? ReadString(detail, "severity") ?? "info").ToLowerInvariant();
        var identifier = ReadString(detail, "identifier") ?? string.Empty;
        var timestamp = ReadTimestamp(root, "iso", "ts");
        var action = SummarizeAction(eventName, tool, detail);
        var details = string.Join(
            " · ",
            new[]
            {
                $"event {eventName}",
                string.IsNullOrWhiteSpace(session) ? null : $"session {Shorten(session)}",
                $"decision {decision}",
                string.IsNullOrWhiteSpace(identifier) ? null : $"finding {Shorten(identifier, 48)}",
                $"severity {severity}",
            }.Where(item => item is not null));

        return new BlackboxAuditEntry(
            timestamp,
            eventName,
            agent,
            Shorten(session),
            tool,
            action,
            decision,
            severity,
            identifier,
            details);
    }

    private static BlackboxFinding ParseFinding(JsonElement root)
    {
        var session = ReadString(root, "session_id") ?? string.Empty;
        return new BlackboxFinding(
            ReadTimestamp(root, "time", "ts"),
            ReadString(root, "identifier") ?? string.Empty,
            ReadString(root, "category") ?? "unknown",
            (ReadString(root, "severity") ?? "info").ToLowerInvariant(),
            ReadString(root, "title") ?? ReadString(root, "evidence") ?? "Finding",
            ReadString(root, "framework") ?? "Unknown",
            Shorten(session),
            ReadString(root, "tool_name") ?? string.Empty,
            (ReadString(root, "decision") ?? string.Empty).ToLowerInvariant(),
            ReadString(root, "source") ?? string.Empty,
            root.TryGetProperty("confirmed", out var confirmed) && confirmed.ValueKind == JsonValueKind.True);
    }

    private static string SummarizeAction(string eventName, string tool, JsonElement detail)
    {
        if (detail.ValueKind != JsonValueKind.Object ||
            !detail.TryGetProperty("args", out var args) ||
            args.ValueKind != JsonValueKind.Object)
        {
            return eventName == "file_access" ? "File access" : tool;
        }

        if (args.TryGetProperty("command", out _))
        {
            return "Shell command (redacted)";
        }

        if (args.TryGetProperty("path", out var path) && path.ValueKind == JsonValueKind.String)
        {
            var extension = Path.GetExtension(path.GetString() ?? string.Empty);
            return string.IsNullOrWhiteSpace(extension)
                ? "File access (redacted)"
                : $"File access {extension} (redacted)";
        }

        if (args.TryGetProperty("url", out _))
        {
            return "Network access (redacted)";
        }

        return $"{tool} (redacted)";
    }

    private static string? ReadString(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object &&
        element.TryGetProperty(propertyName, out var property) &&
        property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private static int ReadInt(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object &&
        element.TryGetProperty(propertyName, out var property) &&
        property.TryGetInt32(out var value)
            ? value
            : 0;

    private static DateTimeOffset? ReadTimestamp(JsonElement element, params string[] names)
    {
        foreach (var name in names)
        {
            if (!element.TryGetProperty(name, out var property))
            {
                continue;
            }

            if (property.ValueKind == JsonValueKind.String &&
                DateTimeOffset.TryParse(
                    property.GetString(),
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal,
                    out var parsed))
            {
                return parsed;
            }

            if (property.ValueKind == JsonValueKind.Number && property.TryGetDouble(out var seconds))
            {
                return DateTimeOffset.FromUnixTimeMilliseconds((long)(seconds * 1000));
            }
        }

        return null;
    }

    private static string Shorten(string value, int length = 8) =>
        value.Length <= length ? value : value[..length];
}
