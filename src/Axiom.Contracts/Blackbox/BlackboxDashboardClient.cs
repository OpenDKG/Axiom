// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Axiom.Contracts.Blackbox;

/// <summary>Structured fields retained from one Blackbox audit event for the detail pane.</summary>
public sealed record BlackboxActivityDetail(
    string SessionId,
    string ToolCallId,
    string TaskId,
    string Workspace,
    string Model,
    string Provider,
    string Command,
    string Path,
    string Mode,
    string Url,
    string Query,
    string Ecosystem,
    string Package,
    string Version,
    string ResultStatus,
    string ResultText,
    long? DurationMs,
    string FindingTitle,
    string FindingIdentifier,
    string FindingCategory,
    string FindingEvidence,
    string FindingSource,
    bool Confirmed)
{
    public string PackageText => string.Join(
        ":",
        new[] { Ecosystem, Package }.Where(value => value.Length > 0)) +
        (Version.Length > 0 ? "@" + Version : string.Empty);
}

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

    public string DateTimeText => Timestamp?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "—";

    public string EventLabel => Event.ToLowerInvariant() switch
    {
        "session_start" => "Session started",
        "session_end" => "Session ended",
        "message_received" => "Message received",
        "pre_api_request" => "API request",
        "pre_tool_call" => "Tool call",
        "post_tool_call" => "Tool result",
        "file_access" => "File access",
        "dependency_install" => "Package install",
        "flagged" => "Threat flagged",
        "blocked" => "Threat blocked",
        _ => string.IsNullOrWhiteSpace(Event)
            ? "Event"
            : char.ToUpperInvariant(Event[0]) + Event[1..].Replace('_', ' '),
    };

    public string Category => Event.ToLowerInvariant() switch
    {
        "session_start" or "session_end" or "message_received" => "sessions",
        "pre_api_request" => "api",
        "pre_tool_call" or "post_tool_call" => "tools",
        "dependency_install" => "installs",
        "file_access" => "file",
        "flagged" or "blocked" => "threats",
        _ => "other",
    };

    public string CategoryLabel => Category switch
    {
        "sessions" => "Session",
        "api" => "API call",
        "tools" => "Tool call",
        "installs" => "Install",
        "file" => "File access",
        "threats" => "Threat",
        _ => "Activity",
    };

    private static readonly Regex SensitivePattern = new(
        @"(?i)\b(token|secret|password|passwd|api[_-]?key|authorization)\b\s*[:=]\s*(""[^""]*""|'[^']*'|[^\s,}\]]+)",
        RegexOptions.Compiled);

    public string SessionFull => Detail?.SessionId is { Length: > 0 } session ? session : Session;

    public string ActionSummary
    {
        get
        {
            var redacted = SensitivePattern.Replace(Action, "$1=[redacted]");
            return redacted.Length <= 180 ? redacted : redacted[..177] + "...";
        }
    }

    public BlackboxActivityDetail? Detail { get; init; }

    public string RawJson { get; init; } = string.Empty;

    public bool IsBlocked => string.Equals(Decision, "block", StringComparison.OrdinalIgnoreCase);

    public bool IsFlagged => string.Equals(Decision, "flag", StringComparison.OrdinalIgnoreCase);

    public bool IsThreat => IsBlocked || IsFlagged ||
                            string.Equals(Event, "flagged", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(Event, "blocked", StringComparison.OrdinalIgnoreCase);

    public string SecurityOutcome =>
        string.Equals(Event, "blocked", StringComparison.OrdinalIgnoreCase) || IsBlocked
            ? "BLOCKED"
            : string.Equals(Event, "flagged", StringComparison.OrdinalIgnoreCase) || IsFlagged
                ? "FLAGGED"
                : "PASSED";

    public bool IsSecurityThreat => SecurityOutcome != "PASSED";

    public string SecurityOutcomeDetail => SecurityOutcome switch
    {
        "BLOCKED" => "Blackbox blocked this action.",
        "FLAGGED" => "Blackbox flagged this action as a threat.",
        _ => "No block or threat flag was recorded for this event.",
    };
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
    public string TimeText => Timestamp?.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture) ?? "ΓÇö";

    public bool IsBlocked => string.Equals(Decision, "block", StringComparison.OrdinalIgnoreCase);

    public bool IsFlagged => string.Equals(Decision, "flag", StringComparison.OrdinalIgnoreCase);

    public string SecurityOutcome => IsBlocked ? "BLOCKED" : IsFlagged ? "FLAGGED" : "OBSERVED";

    public bool IsSecurityThreat => IsBlocked || IsFlagged;
}

public sealed record BlackboxAuditPage(IReadOnlyList<BlackboxAuditEntry> Entries, int Total);

public sealed record BlackboxFindingPage(IReadOnlyList<BlackboxFinding> Findings, int Total);

/// <summary>
/// State of Blackbox's local verified-graph sync. Nullable counters are deliberate: a null means
/// the local node could not report a value, not that the value is zero.
/// </summary>
public sealed record BlackboxVerifiedSync(
    string State,
    int? GraphAssets,
    int? DownloadedAssets,
    long? DownloadedTriples,
    int? CompiledAssets,
    int VerifiedRules,
    double? PercentDownloaded,
    double? PercentCompiled,
    string CheckedAt,
    BlackboxLookupState Lookups,
    string Phase,
    string PhaseText,
    DateTimeOffset? RunningSince,
    string LastProgress)
{
    public bool IsOffline => string.Equals(State, "unavailable", StringComparison.OrdinalIgnoreCase);

    public bool IsSyncing => string.Equals(State, "syncing", StringComparison.OrdinalIgnoreCase);

    public double DisplayPercent => Math.Clamp(PercentCompiled ?? 0, 0, 100);
}

public sealed record BlackboxLookupState(string State, string Label, string Text);

/// <summary>One threat in the verified public graph exposed by the local dashboard.</summary>
public sealed record BlackboxGraphThreat(
    string Identifier,
    string Name,
    string Category,
    string Severity,
    string Ecosystems,
    string Source)
{
    public string DisplayName => string.IsNullOrWhiteSpace(Name) ? Identifier : Name;

    public string CategoryLabel => Category.ToLowerInvariant() switch
    {
        "dependency" => "Dependency",
        "injection" => "Prompt injection",
        "escalation" => "Escalation",
        "fileaccess" => "File access",
        "skill" => "Suspicious skill",
        "secret" => "Secret exposure",
        "ioc" => "IOC",
        _ => "Other",
    };

    public string SeverityLabel => string.IsNullOrWhiteSpace(Severity)
        ? "unknown"
        : char.ToUpperInvariant(Severity[0]) + Severity[1..].ToLowerInvariant();
}

public sealed record BlackboxGraphPage(
    IReadOnlyList<BlackboxGraphThreat> Threats,
    int Total,
    bool Partial)
{
    public IReadOnlyDictionary<string, int> CategoryTotals { get; init; } =
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
}

public sealed record BlackboxSyncResult(bool Ok, string Message);

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
            _http = new HttpClient { BaseAddress = uri, Timeout = TimeSpan.FromSeconds(15) };
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _http.BaseAddress ??= uri;
            _http.Timeout = TimeSpan.FromSeconds(15);
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

    /// <summary>
    /// Reads the dashboard's verified-sync meter. This is a server-owned state machine: never
    /// infer "synced" from a rule count, and never turn a missing value into zero.
    /// </summary>
    public async Task<BlackboxVerifiedSync> GetVerifiedSyncAsync(CancellationToken cancellationToken)
    {
        using var document = await GetJsonAsync("api/verified-sync", cancellationToken).ConfigureAwait(false);
        var root = document.RootElement;
        var lookups = ReadObject(root, "lookups");

        return new BlackboxVerifiedSync(
            ReadString(root, "state") ?? "unknown",
            ReadNullableInt(root, "graph_assets"),
            ReadNullableInt(root, "downloaded_assets"),
            ReadNullableLong(root, "downloaded_triples"),
            ReadNullableInt(root, "compiled_assets"),
            ReadInt(root, "verified_rules"),
            ReadNullableDouble(root, "percent_downloaded"),
            ReadNullableDouble(root, "percent_compiled"),
            ReadString(root, "checked_at") ?? string.Empty,
            new BlackboxLookupState(
                ReadString(lookups, "state") ?? "unknown",
                ReadString(lookups, "label") ?? "Checking…",
                ReadString(lookups, "text") ?? string.Empty),
            ReadString(root, "phase") ?? string.Empty,
            ReadString(root, "phase_text") ?? string.Empty,
            ReadTimestamp(root, "running_since"),
            ReadFlexibleString(root, "last_progress"));
    }

    /// <summary>
    /// Reads the verified public graph. The dashboard caps page size; the caller should request a
    /// bounded page instead of trying to mirror the whole graph into memory.
    /// </summary>
    public async Task<BlackboxGraphPage> GetVerifiedGraphAsync(
        int limit,
        int offset,
        CancellationToken cancellationToken)
    {
        limit = Math.Clamp(limit, 1, 500);
        offset = Math.Max(0, offset);

        using var document = await GetJsonAsync(
            $"api/graph?tier=public&limit={limit.ToString(CultureInfo.InvariantCulture)}&offset={offset.ToString(CultureInfo.InvariantCulture)}",
            cancellationToken).ConfigureAwait(false);

        var threats = new List<BlackboxGraphThreat>();
        if (document.RootElement.TryGetProperty("threats", out var array) &&
            array.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in array.EnumerateArray())
            {
                var identifier = ReadString(item, "identifier") ?? string.Empty;
                if (identifier.Length == 0)
                {
                    continue;
                }

                threats.Add(new BlackboxGraphThreat(
                    identifier,
                    ReadString(item, "name") ?? string.Empty,
                    ReadString(item, "category") ?? "other",
                    ReadString(item, "severity") ?? "info",
                    ReadEcosystems(item),
                    ReadString(item, "source") ?? string.Empty));
            }
        }

        return new BlackboxGraphPage(
            threats,
            ReadInt(document.RootElement, "total"),
            ReadBool(document.RootElement, "partial"))
        {
            CategoryTotals = ReadCategoryTotals(document.RootElement),
        };
    }

    /// <summary>
    /// Requests an asynchronous verified-graph sync from the local dashboard. The call only asks
    /// the daemon to start; callers must poll <see cref="GetVerifiedSyncAsync"/> for progress.
    /// </summary>
    public async Task<BlackboxSyncResult> RequestSyncAsync(CancellationToken cancellationToken)
    {
        var token = await GetSessionTokenAsync(cancellationToken).ConfigureAwait(false);
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/sync")
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        request.Headers.Add("X-Blackbox-Token", token);

        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await ReadBoundedAsync(response, cancellationToken).ConfigureAwait(false);
        using var document = Parse(body);
        var root = document.RootElement;

        if (!response.IsSuccessStatusCode)
        {
            var errors = ReadErrors(root);
            return new BlackboxSyncResult(false, errors.FirstOrDefault() ?? "Blackbox rejected the sync request.");
        }

        if (root.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.False)
        {
            var errors = ReadErrors(root);
            return new BlackboxSyncResult(false, errors.FirstOrDefault() ?? "Blackbox rejected the sync request.");
        }

        return new BlackboxSyncResult(
            true,
            ReadString(root, "message") ?? "Sync requested; the local dashboard will report progress.");
    }

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
        var detail = ReadObject(root, "detail");
        var finding = ReadObject(root, "finding");
        var args = ReadObject(detail, "args");
        var eventName = ReadString(root, "event") ?? "event";
        var agent = ReadString(root, "framework") ?? ReadString(detail, "framework") ?? "Unknown";
        var session = ReadString(detail, "session_id") ?? ReadString(root, "session_id") ?? string.Empty;
        var toolCallId = ReadString(detail, "tool_call_id") ?? string.Empty;
        var taskId = ReadString(detail, "task_id") ?? string.Empty;
        var workspace = ReadString(root, "workspace") ?? ReadString(detail, "workspace") ?? string.Empty;
        var tool = FirstNonEmpty(
            ReadString(detail, "tool_name"),
            ReadString(root, "tool"),
            ReadString(finding, "tool_name"),
            eventName);
        var decision = FirstNonEmpty(
            ReadString(detail, "decision"),
            ReadString(finding, "decision"),
            eventName == "blocked" ? "block" : eventName == "flagged" ? "flag" : "observed")
            .ToLowerInvariant();
        if (detail.ValueKind == JsonValueKind.Object &&
            detail.TryGetProperty("blocked", out var blocked) &&
            blocked.ValueKind == JsonValueKind.Array &&
            blocked.GetArrayLength() > 0)
        {
            decision = "block";
        }

        var severity = FirstNonEmpty(
            ReadString(root, "severity"),
            ReadString(finding, "severity"),
            ReadString(detail, "severity"),
            "info").ToLowerInvariant();
        var identifier = FirstNonEmpty(ReadString(detail, "identifier"), ReadString(finding, "identifier"));
        var model = FirstNonEmpty(ReadString(detail, "model"), ReadString(root, "model"));
        var provider = FirstNonEmpty(ReadString(detail, "provider"), ReadString(root, "provider"));
        var command = FirstNonEmpty(
            ReadArgString(args, "command"),
            ReadArgString(args, "cmd"),
            ReadArgString(args, "script"));
        var path = FirstNonEmpty(
            ReadArgString(args, "path"),
            ReadArgString(args, "file"),
            ReadArgString(args, "filename"),
            ReadString(root, "path"));
        var mode = FirstNonEmpty(ReadString(root, "mode"), ReadString(detail, "mode"));
        var url = ReadArgString(args, "url");
        var query = ReadArgString(args, "query");
        var ecosystem = FirstNonEmpty(ReadString(root, "ecosystem"), ReadString(detail, "ecosystem"));
        var packageName = FirstNonEmpty(ReadString(root, "name"), ReadString(detail, "name"));
        var version = FirstNonEmpty(ReadString(root, "version"), ReadString(detail, "version"));
        var resultStatus = ReadResultStatus(detail);
        var resultText = ReadResultText(detail);
        var durationMs = ReadLong(detail, "duration_ms");
        var findingTitle = FirstNonEmpty(ReadString(finding, "title"), ReadString(finding, "evidence"));
        var findingEvidence = ReadString(finding, "evidence") ?? string.Empty;
        var findingCategory = ReadString(finding, "category") ?? string.Empty;
        var findingSource = ReadString(finding, "source") ?? string.Empty;
        var confirmed = ReadBool(finding, "confirmed");
        var timestamp = ReadTimestamp(root, "iso", "ts");
        var action = SummarizeAction(
            eventName, tool, detail, finding, session, tool, command, path, mode, url, query,
            ecosystem, packageName, version, model, provider, resultStatus);
        var details = BuildActivityDetails(
            eventName, session, decision, severity, identifier, resultStatus, durationMs);
        var detailRecord = new BlackboxActivityDetail(
            session,
            toolCallId,
            taskId,
            workspace,
            model,
            provider,
            command,
            path,
            mode,
            url,
            query,
            ecosystem,
            packageName,
            version,
            resultStatus,
            resultText,
            durationMs,
            findingTitle,
            identifier,
            findingCategory,
            findingEvidence,
            findingSource,
            confirmed);

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
            details)
        {
            Detail = detailRecord,
            RawJson = root.GetRawText(),
        };
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

    private static string SummarizeAction(
        string eventName,
        string tool,
        JsonElement detail,
        JsonElement finding,
        string session,
        string toolName,
        string command,
        string path,
        string mode,
        string url,
        string query,
        string ecosystem,
        string packageName,
        string version,
        string model,
        string provider,
        string resultStatus)
    {
        var lower = eventName.ToLowerInvariant();
        if (lower is "flagged" or "blocked")
        {
            return FirstNonEmpty(
                ReadString(finding, "title"),
                ReadString(finding, "identifier"),
                "Threat");
        }

        if (lower == "dependency_install")
        {
            var package = string.Join(
                ":",
                new[] { ecosystem, packageName }.Where(value => value.Length > 0)) +
                (version.Length > 0 ? "@" + version : string.Empty);
            return FirstNonEmpty(package, "Package install");
        }

        if (lower == "file_access")
        {
            return FirstNonEmpty(
                string.Join(" ", new[] { mode, path }.Where(value => value.Length > 0)),
                "File access");
        }

        if (lower == "pre_tool_call" || lower == "post_tool_call")
        {
            var action = ToolActionText(toolName, ReadObject(detail, "args"));
            if (action.Length > 0)
            {
                return action;
            }

            return FirstNonEmpty(resultStatus, lower == "post_tool_call" ? "Tool result" : tool);
        }

        if (lower == "pre_api_request")
        {
            return FirstNonEmpty(
                string.Join(" ", new[] { provider, model }.Where(value => value.Length > 0)),
                "API request");
        }

        if (lower == "session_start")
        {
            return "Session " + Shorten(session) + " started";
        }

        if (lower == "session_end")
        {
            var interrupted = ReadBool(detail, "interrupted");
            return "Session " + Shorten(session) + " ended" + (interrupted ? " (interrupted)" : string.Empty);
        }

        if (lower == "message_received")
        {
            return "Message received";
        }

        return FirstNonEmpty(command, path, url, query, tool);
    }

    private static string BuildActivityDetails(
        string eventName,
        string session,
        string decision,
        string severity,
        string identifier,
        string resultStatus,
        long? durationMs)
    {
        var parts = new List<string> { $"event {eventName}" };
        if (session.Length > 0)
        {
            parts.Add($"session {Shorten(session)}");
        }

        if (!string.Equals(decision, "observed", StringComparison.OrdinalIgnoreCase))
        {
            parts.Add($"decision {decision}");
        }

        if (!string.Equals(severity, "info", StringComparison.OrdinalIgnoreCase))
        {
            parts.Add($"severity {severity}");
        }

        if (identifier.Length > 0)
        {
            parts.Add($"finding {Shorten(identifier, 48)}");
        }

        if (resultStatus.Length > 0)
        {
            parts.Add(resultStatus);
        }

        if (durationMs is > 0)
        {
            parts.Add(FormatDuration(durationMs.Value));
        }

        return string.Join(" · ", parts);
    }

    private static string ReadResultStatus(JsonElement detail)
    {
        if (detail.ValueKind != JsonValueKind.Object ||
            !detail.TryGetProperty("result", out var result))
        {
            return string.Empty;
        }

        if (result.ValueKind == JsonValueKind.String)
        {
            var text = result.GetString() ?? string.Empty;
            return text.StartsWith("BLOCKED", StringComparison.OrdinalIgnoreCase)
                ? "blocked"
                : text.Length > 0 ? "result" : string.Empty;
        }

        if (result.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        if (result.TryGetProperty("error", out var error) &&
            error.ValueKind == JsonValueKind.String &&
            error.GetString() is { Length: > 0 } errorText)
        {
            return errorText.StartsWith("BLOCKED", StringComparison.OrdinalIgnoreCase)
                ? "blocked"
                : "error";
        }

        if (result.TryGetProperty("exit_code", out var exitCode))
        {
            return exitCode.ValueKind == JsonValueKind.Number && exitCode.TryGetInt32(out var code)
                ? code == 0 ? "exit 0" : $"exit {code}"
                : "exit";
        }

        return string.Empty;
    }

    private static string ReadResultText(JsonElement detail)
    {
        if (detail.ValueKind != JsonValueKind.Object ||
            !detail.TryGetProperty("result", out var result))
        {
            return string.Empty;
        }

        return result.ValueKind == JsonValueKind.String
            ? result.GetString() ?? string.Empty
            : result.GetRawText();
    }

    private static string ToolActionText(string toolName, JsonElement args)
    {
        if (args.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        foreach (var name in new[] { "command", "cmd", "script", "path", "file", "filename", "url", "query" })
        {
            var value = ReadArgString(args, name);
            if (value.Length > 0)
            {
                return value;
            }
        }

        foreach (var property in args.EnumerateObject())
        {
            if (property.Value.ValueKind == JsonValueKind.String &&
                property.Value.GetString() is { Length: > 0 } value)
            {
                return property.Name + "=" + value;
            }
        }

        return toolName;
    }

    private static JsonElement ReadObject(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object &&
        element.TryGetProperty(propertyName, out var property) &&
        property.ValueKind == JsonValueKind.Object
            ? property
            : default;

    private static string ReadArgString(JsonElement args, string propertyName) =>
        args.ValueKind == JsonValueKind.Object &&
        args.TryGetProperty(propertyName, out var property) &&
        property.ValueKind == JsonValueKind.String
            ? property.GetString() ?? string.Empty
            : string.Empty;

    private static bool ReadBool(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object &&
        element.TryGetProperty(propertyName, out var property) &&
        property.ValueKind == JsonValueKind.True;

    private static long? ReadLong(JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty(propertyName, out var property))
        {
            return null;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetInt64(out var number))
        {
            return number;
        }

        return null;
    }

    private static string FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private static string FormatDuration(long milliseconds) => milliseconds switch
    {
        < 1000 => $"{milliseconds} ms",
        < 60_000 => $"{milliseconds / 1000.0:0.0} s",
        _ => $"{milliseconds / 60_000.0:0.0} min",
    };

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

    private static int? ReadNullableInt(JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind != JsonValueKind.Number)
        {
            return null;
        }

        if (property.TryGetInt32(out var value))
        {
            return value;
        }

        return property.TryGetDouble(out var number)
            ? (int)Math.Round(number)
            : null;
    }

    private static long? ReadNullableLong(JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind != JsonValueKind.Number)
        {
            return null;
        }

        if (property.TryGetInt64(out var value))
        {
            return value;
        }

        return property.TryGetDouble(out var number)
            ? (long)Math.Round(number)
            : null;
    }

    private static double? ReadNullableDouble(JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return property.ValueKind == JsonValueKind.Number &&
               property.TryGetDouble(out var value)
            ? value
            : null;
    }

    private static string ReadFlexibleString(JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty(propertyName, out var property))
        {
            return string.Empty;
        }

        return property.ValueKind switch
        {
            JsonValueKind.String => property.GetString() ?? string.Empty,
            JsonValueKind.Null or JsonValueKind.Undefined => string.Empty,
            _ => property.GetRawText(),
        };
    }

    private static Dictionary<string, int> ReadCategoryTotals(JsonElement element)
    {
        var totals = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty("category_totals", out var categories) ||
            categories.ValueKind != JsonValueKind.Object)
        {
            return totals;
        }

        foreach (var property in categories.EnumerateObject())
        {
            if (property.Value.ValueKind == JsonValueKind.Number &&
                property.Value.TryGetInt32(out var count) &&
                count >= 0)
            {
                totals[property.Name] = count;
            }
        }

        return totals;
    }

    private static string ReadEcosystems(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty("ecosystems", out var property))
        {
            return string.Empty;
        }

        if (property.ValueKind == JsonValueKind.String)
        {
            return property.GetString() ?? string.Empty;
        }

        if (property.ValueKind == JsonValueKind.Array)
        {
            return string.Join(
                ", ",
                property.EnumerateArray()
                    .Where(item => item.ValueKind == JsonValueKind.String)
                    .Select(item => item.GetString())
                    .Where(item => !string.IsNullOrWhiteSpace(item)));
        }

        return string.Empty;
    }

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
