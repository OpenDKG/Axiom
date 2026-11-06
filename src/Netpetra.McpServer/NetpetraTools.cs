// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using ModelContextProtocol.Server;
using Netpetra.Contracts.Firewall;
using Netpetra.Contracts.History;
using Netpetra.Contracts.Monitoring;

namespace Netpetra.McpServer;

/// <summary>
/// Read-only MCP tools. The agent is an analyst: no tool can apply firewall rules, terminate a
/// process, read arbitrary files or execute a command.
/// </summary>
[McpServerToolType]
public sealed class NetpetraTools
{
    private const string SchemaVersion = "1";

    private static readonly NetpetraServiceClient Client = new();

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        MaxDepth = 16,
    };

    private static readonly string[] AnalysisRecommendations =
    [
        "Inspect the executable path and recent history for the same process.",
        "Correlate the destination with user-initiated activity and known services.",
        "Treat a newly observed public endpoint as a lead, not a verdict.",
    ];

    private static readonly string[] AnalysisLimitations =
    [
        "No packet contents, TLS metadata, DNS history or per-process bytes are observed.",
        "No public-IP reputation was queried.",
        "Absence of an alert is not proof of safety.",
    ];

    private static readonly string[] ReportFalsePositiveConsiderations =
    [
        "Private, loopback and development destinations are not treated as malicious.",
        "Unsigned executables and unfamiliar public addresses are not proof of malware.",
        "CDN/shared hosting and AI API traffic can produce unfamiliar destinations.",
    ];

    private static readonly string[] ReportRecommendedActions =
    [
        "Review high-frequency and newly observed public destinations with the process path.",
        "Correlate findings with user activity before proposing any enforcement.",
        "Use the firewall page for an explicit, human-approved rule if needed.",
    ];

    private static readonly string[] ReportMissingEvidence =
    [
        "Per-process byte counters (ETW not implemented).",
        "DNS/TLS payload evidence.",
        "Reputation provider results.",
        "Windows Filtering Platform block events.",
        "Rows without an observed remote endpoint remain unassessed.",
    ];

    [McpServerTool(Name = "netpetra_get_status"), Description("Return Axiom service health, monitoring source, data quality, last snapshot, capabilities and limitations. Read-only.")]
    public static async Task<string> GetStatus()
    {
        return await GuardAsync(async () =>
        {
            var health = await Client.GetHealthAsync(CancellationToken.None);
            var capabilities = await Client.GetCapabilitiesAsync(CancellationToken.None);

            return new
            {
                schemaVersion = SchemaVersion,
                service = new
                {
                    status = health.Status,
                    uptimeSeconds = health.UptimeSeconds,
                    source = health.SourceName,
                    pollIntervalSeconds = health.PollIntervalSeconds,
                    lastCaptureUtc = health.LastCaptureUtc,
                    connectionCount = health.ConnectionCount,
                    processCount = health.ProcessCount,
                    lastError = health.LastError,
                },
                capabilities = new
                {
                    protocolVersion = capabilities.ProtocolVersion,
                    monitoring = capabilities.Monitoring,
                    firewallWrites = capabilities.FirewallWrites,
                    milestone = capabilities.Milestone,
                    commands = capabilities.Commands,
                },
                dataQuality = new
                {
                    perProcessBytes = "not measured (ETW requires elevation and is deferred)",
                    processIdentity = "IP Helper owner table plus resolved executable path",
                    firewallEnforcement = "read-only unless the explicit service write gate is open",
                },
                limitations = health.Limitations,
            };
        });
    }

    [McpServerTool(Name = "netpetra_list_connections"), Description("List current observed sockets with bounded filters. Returns connection identifiers, process attribution and data quality; no packet contents.")]
    public static async Task<string> ListConnections(
        [Description("Only include sockets first observed within this many minutes. 0 means all current sockets; maximum 1440. Default 0.")] int windowMinutes = 0,
        [Description("Case-insensitive process/application name fragment.")] string? process = null,
        [Description("Exact process ID.")] int? pid = null,
        [Description("tcp or udp.")] string? protocol = null,
        [Description("Remote IP address fragment.")] string? remoteIp = null,
        [Description("Remote port.")] int? port = null,
        [Description("Connection state fragment, e.g. Established.")] string? state = null,
        [Description("inbound, outbound or unknown.")] string? direction = null,
        [Description("Maximum rows, 1-500. Default 100.")] int limit = 100)
    {
        return await GuardAsync(async () =>
        {
            var snapshot = await Client.GetSnapshotAsync(CancellationToken.None);
            var now = DateTimeOffset.UtcNow;
            var window = TimeSpan.FromMinutes(Math.Clamp(windowMinutes, 0, 1440));
            var rows = snapshot.Connections
                .Where(connection => windowMinutes <= 0 || now - connection.FirstObservedUtc <= window)
                .Where(connection => process is null ||
                                     connection.AppDisplayName.Contains(process, StringComparison.OrdinalIgnoreCase) ||
                                     connection.AppPath.Contains(process, StringComparison.OrdinalIgnoreCase))
                .Where(connection => pid is null || connection.ProcessId == pid)
                .Where(connection => protocol is null ||
                                     string.Equals(connection.Protocol.ToString(), protocol, StringComparison.OrdinalIgnoreCase))
                .Where(connection => remoteIp is null || connection.RemoteEndpoint.Contains(remoteIp, StringComparison.OrdinalIgnoreCase))
                .Where(connection => port is null || EndpointPort(connection.RemoteEndpoint) == port)
                .Where(connection => state is null || connection.State.Contains(state, StringComparison.OrdinalIgnoreCase))
                .Where(connection => direction is null ||
                                     string.Equals(connection.Direction.ToString(), direction, StringComparison.OrdinalIgnoreCase))
                .Take(Math.Clamp(limit, 1, 500))
                .Select(ToConnectionRow)
                .ToArray();

            return new
            {
                schemaVersion = SchemaVersion,
                capturedUtc = snapshot.CapturedUtc,
                source = snapshot.SourceName,
                totalObserved = snapshot.Connections.Count,
                returned = rows.Length,
                rows,
                limitations = snapshot.Limitations,
            };
        });
    }

    [McpServerTool(Name = "netpetra_get_connection_history"), Description("Query bounded stored connection history with pagination. Returns actual coverage and total count.")]
    public static async Task<string> GetConnectionHistory(
        [Description("ISO-8601 UTC start. Default now minus 24 hours.")] string? fromUtc = null,
        [Description("ISO-8601 UTC end. Default now.")] string? toUtc = null,
        [Description("Matches application, path, remote endpoint or PID.")] string? search = null,
        [Description("Maximum rows, 1-500. Default 200.")] int limit = 200,
        [Description("Offset, 0 or greater.")] int offset = 0)
    {
        return await GuardAsync(async () =>
        {
            var to = ParseUtc(toUtc) ?? DateTimeOffset.UtcNow;
            var from = ParseUtc(fromUtc) ?? to.AddHours(-24);
            if (from >= to)
            {
                throw new ArgumentException("fromUtc must be before toUtc.");
            }

            var page = await Client.QueryHistoryAsync(new HistoryQuery
            {
                FromUtc = from,
                ToUtc = to,
                Search = string.IsNullOrWhiteSpace(search) ? null : search.Trim(),
                Limit = Math.Clamp(limit, 1, 500),
                Offset = Math.Max(0, offset),
            }, CancellationToken.None);

            return new
            {
                schemaVersion = SchemaVersion,
                requestedFromUtc = from,
                requestedToUtc = to,
                returned = page.Rows.Count,
                totalCount = page.TotalCount,
                offset = Math.Max(0, offset),
                queriedUtc = page.QueriedUtc,
                rows = page.Rows.Select(ToHistoryRow).ToArray(),
                coverage = "Stored observations only. The actual available range may be shorter than requested.",
            };
        });
    }

    [McpServerTool(Name = "netpetra_inspect_process"), Description("Inspect one observed process: executable path, PIDs, endpoints, first observation and data quality. Signature/hash are explicitly unavailable unless implemented.")]
    public static async Task<string> InspectProcess(
        [Description("Exact process ID.")] int? pid = null,
        [Description("Case-insensitive executable/application name.")] string? process = null)
    {
        return await GuardAsync(async () =>
        {
            if (pid is null && string.IsNullOrWhiteSpace(process))
            {
                throw new ArgumentException("Provide pid or process.");
            }

            var snapshot = await Client.GetSnapshotAsync(CancellationToken.None);
            var matches = snapshot.Connections
                .Where(connection => pid is null || connection.ProcessId == pid)
                .Where(connection => string.IsNullOrWhiteSpace(process) ||
                                     connection.AppDisplayName.Contains(process, StringComparison.OrdinalIgnoreCase) ||
                                     connection.AppPath.Contains(process, StringComparison.OrdinalIgnoreCase))
                .ToArray();

            if (matches.Length == 0)
            {
                return new
                {
                    schemaVersion = SchemaVersion,
                    status = "NOT_OBSERVED",
                    message = "No current socket matched this process. Absence here does not prove the process is inactive.",
                    capturedUtc = snapshot.CapturedUtc,
                };
            }

            return new
            {
                schemaVersion = SchemaVersion,
                capturedUtc = snapshot.CapturedUtc,
                applications = matches
                    .GroupBy(connection => connection.AppPath, StringComparer.OrdinalIgnoreCase)
                    .Select(group => new
                    {
                        name = group.First().AppDisplayName,
                        path = string.IsNullOrWhiteSpace(group.Key) ? null : group.Key,
                        pids = group.Select(connection => connection.ProcessId).Distinct().OrderBy(value => value).ToArray(),
                        quality = group.Select(connection => connection.Quality.ToString()).Distinct().ToArray(),
                        firstObservedUtc = group.Min(connection => connection.FirstObservedUtc),
                        endpoints = group.Select(connection => new
                        {
                            protocol = connection.Protocol.ToString(),
                            local = connection.LocalEndpoint,
                            remote = connection.RemoteEndpoint,
                            state = connection.State,
                            direction = connection.Direction.ToString(),
                            loopback = connection.IsLoopback,
                            newObservation = connection.IsNew,
                            ruleStatus = connection.RuleStatus.ToString(),
                        }).Take(200).ToArray(),
                    }).ToArray(),
                unavailableEvidence = new
                {
                    fileHash = "not available in this read-only IPC contract",
                    authenticode = "not available in this read-only IPC contract",
                    parentProcess = "not exposed by IP Helper",
                    commandLine = "not exposed by IP Helper",
                },
            };
        });
    }

    [McpServerTool(Name = "netpetra_analyze_connection"), Description("Deterministic read-only risk analysis for one observed connection. Returns evidence, confidence and uncertainty; never a SAFE verdict.")]
    public static async Task<string> AnalyzeConnection(
        [Description("Exact local PID.")] int? pid = null,
        [Description("Remote endpoint, e.g. 203.0.113.10:443.")] string? remoteEndpoint = null,
        [Description("Local endpoint to disambiguate.")] string? localEndpoint = null)
    {
        return await GuardAsync(async () =>
        {
            if (pid is null && string.IsNullOrWhiteSpace(remoteEndpoint) && string.IsNullOrWhiteSpace(localEndpoint))
            {
                throw new ArgumentException("Provide pid, remoteEndpoint or localEndpoint so the analysis is deterministic.");
            }

            var snapshot = await Client.GetSnapshotAsync(CancellationToken.None);
            var match = snapshot.Connections
                .Where(connection => pid is null || connection.ProcessId == pid)
                .Where(connection => remoteEndpoint is null ||
                                     connection.RemoteEndpoint.Contains(remoteEndpoint, StringComparison.OrdinalIgnoreCase))
                .Where(connection => localEndpoint is null ||
                                     connection.LocalEndpoint.Contains(localEndpoint, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(connection => connection.FirstObservedUtc)
                .FirstOrDefault();

            if (match is null)
            {
                return new
                {
                    schemaVersion = SchemaVersion,
                    risk = "INSUFFICIENT_DATA",
                    confidence = "low",
                    evidence = Array.Empty<string>(),
                    message = "No current connection matched. Historical evidence was not assumed.",
                };
            }

            var remoteHost = EndpointHost(match.RemoteEndpoint);
            var hasRemote = !string.IsNullOrWhiteSpace(remoteHost);
            var isPrivate = hasRemote && IsPrivateOrLoopback(remoteHost);
            var evidence = new List<string>
            {
                $"process={match.AppDisplayName}, pid={match.ProcessId}, quality={match.Quality}",
                $"protocol={match.Protocol}, direction={match.Direction}, state={match.State}",
                $"remote={(string.IsNullOrWhiteSpace(match.RemoteEndpoint) ? "unknown" : match.RemoteEndpoint)}",
                match.IsNew ? "first observed in the current observation window" : "observed before the current window",
                match.IsLoopback
                    ? "loopback destination"
                    : !hasRemote
                        ? "remote endpoint was not observed"
                        : isPrivate
                            ? "private/local destination"
                            : "public destination",
            };

            var risk = !hasRemote
                ? "INSUFFICIENT_DATA"
                : match.IsLoopback || isPrivate
                    ? "LOW_OBSERVED_RISK"
                    : "UNKNOWN";
            var confidence = hasRemote && match.Quality == DataQuality.Observed ? "medium" : "low";
            if (hasRemote && match.IsNew && !match.IsLoopback && !isPrivate)
            {
                risk = "SUSPICIOUS";
                confidence = "low";
                evidence.Add("newly observed public destination is an anomaly signal, not proof of malice");
            }

            if (match.RuleStatus == ConnectionRuleStatus.BlockedByOwnedRule)
            {
                evidence.Add("an owned firewall rule reports the connection as blocked; this is a rule state, not proof that this observation was prevented");
            }

            return new
            {
                schemaVersion = SchemaVersion,
                risk,
                confidence,
                evidence,
                reputation = "unavailable; no reputation provider is configured in this read-only foundation",
                recommendations = AnalysisRecommendations,
                limitations = AnalysisLimitations,
            };
        });
    }

    [McpServerTool(Name = "netpetra_get_threat_alerts"), Description("Return locally stored threat alerts if an alert store exists. This foundation build has no alert store and reports that explicitly.")]
    public static Task<string> GetThreatAlerts(
        [Description("Maximum alerts, 1-200. Default 50.")] int limit = 50)
    {
        var boundedLimit = Math.Clamp(limit, 1, 200);
        return Task.FromResult(Serialize(new
        {
            schemaVersion = SchemaVersion,
            status = "UNAVAILABLE",
            limit = boundedLimit,
            alerts = Array.Empty<object>(),
            message = "No Axiom threat-alert store exists in this foundation build. Empty is not a clean bill of health.",
        }));
    }

    [McpServerTool(Name = "netpetra_get_reputation"), Description("Query locally cached reputation, or report that no provider/cache is configured. This foundation build does not query external providers.")]
    public static Task<string> GetReputation(
        [Description("Public IP, domain or executable SHA-256.")] string indicator,
        [Description("ip, domain or sha256. Optional; inferred when obvious.")] string? indicatorType = null)
    {
        var trimmed = (indicator ?? string.Empty).Trim();
        return Task.FromResult(Serialize(new
        {
            schemaVersion = SchemaVersion,
            status = "UNAVAILABLE",
            indicator = trimmed.Length > 200 ? trimmed[..200] : trimmed,
            indicatorType = indicatorType ?? InferIndicatorType(trimmed),
            source = (string?)null,
            confidence = "none",
            current = false,
            message = "No local reputation cache or permitted provider is configured. Unknown is not clean.",
        }));
    }

    [McpServerTool(Name = "netpetra_get_firewall_rules"), Description("Return read-only Axiom-owned firewall rules, capability and write-gate state. Does not change Windows Firewall.")]
    public static async Task<string> GetFirewallRules()
    {
        return await GuardAsync(async () =>
        {
            var snapshot = await Client.GetFirewallRulesAsync(CancellationToken.None);
            return new
            {
                schemaVersion = SchemaVersion,
                capability = snapshot.Capability,
                writesEnabled = snapshot.WritesEnabled,
                rules = snapshot.Rules,
                enforcementNote = "A rule existing is not evidence that it blocked the observed connection. Only explicit verification supports that claim.",
            };
        });
    }

    [McpServerTool(Name = "netpetra_generate_security_report"), Description("Generate a bounded evidence-based summary from current Axiom observations. It does not claim safety and does not modify the host.")]
    public static async Task<string> GenerateSecurityReport(
        [Description("History window in hours, 1-168. Default 24.")] int hours = 24,
        [Description("Maximum connections considered, 1-500. Default 200.")] int limit = 200)
    {
        return await GuardAsync(async () =>
        {
            var to = DateTimeOffset.UtcNow;
            var from = to.AddHours(-Math.Clamp(hours, 1, 168));
            var page = await Client.QueryHistoryAsync(new HistoryQuery
            {
                FromUtc = from,
                ToUtc = to,
                Limit = Math.Clamp(limit, 1, 500),
            }, CancellationToken.None);

            var apps = page.Rows
                .GroupBy(row => row.AppDisplayName, StringComparer.OrdinalIgnoreCase)
                .Select(group => new { name = group.Key, connections = group.Count() })
                .OrderByDescending(item => item.connections)
                .Take(20)
                .ToArray();

            var remoteHosts = page.Rows
                .Select(row => EndpointHost(row.RemoteEndpoint))
                .ToArray();
            var unknownRemoteConnections = remoteHosts.Count(string.IsNullOrWhiteSpace);
            var publicDestinations = remoteHosts
                .Where(host => host.Length > 0 && !IsPrivateOrLoopback(host))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(50)
                .ToArray();

            return new
            {
                schemaVersion = SchemaVersion,
                coverage = new
                {
                    requestedFromUtc = from,
                    requestedToUtc = to,
                    sampleSize = page.Rows.Count,
                    totalStored = page.TotalCount,
                    note = "Only stored observations are represented; the sample is bounded and the available range may be shorter.",
                },
                assessment = "UNASSESSED",
                message = "No reputation or alert evidence was available. This report is not a clean bill of health.",
                processesExamined = apps,
                destinationsExamined = publicDestinations.Length,
                publicDestinations,
                unknownRemoteConnections,
                confirmedMaliciousIndicators = Array.Empty<object>(),
                suspiciousUnconfirmed = Array.Empty<object>(),
                unassessedConnectionsInSample = page.Rows.Count,
                falsePositiveConsiderations = ReportFalsePositiveConsiderations,
                recommendedActions = ReportRecommendedActions,
                missingEvidence = ReportMissingEvidence,
            };
        });
    }

    private static async Task<string> GuardAsync(Func<Task<object?>> action)
    {
        try
        {
            return Serialize(await action().ConfigureAwait(false));
        }
        catch (ServiceUnavailableException exception)
        {
            return Serialize(new
            {
                schemaVersion = SchemaVersion,
                status = "UNAVAILABLE",
                error = exception.Message,
                message = "Axiom service is not available. No data was fabricated.",
            });
        }
        catch (ArgumentException exception)
        {
            return Serialize(new
            {
                schemaVersion = SchemaVersion,
                status = "INVALID_INPUT",
                error = exception.Message,
            });
        }
        catch (Exception exception) when (exception is IOException or JsonException)
        {
            return Serialize(new
            {
                schemaVersion = SchemaVersion,
                status = "ERROR",
                error = exception.Message,
            });
        }
    }

    private static string Serialize(object? value) => JsonSerializer.Serialize(value, JsonOptions);

    private static object ToConnectionRow(LiveConnection connection) => new
    {
        id = $"{connection.ProcessId}|{connection.Protocol}|{connection.LocalEndpoint}|{connection.RemoteEndpoint}",
        app = connection.AppDisplayName,
        path = string.IsNullOrWhiteSpace(connection.AppPath) ? null : connection.AppPath,
        pid = connection.ProcessId,
        protocol = connection.Protocol.ToString(),
        local = connection.LocalEndpoint,
        remote = connection.RemoteEndpoint,
        state = connection.State,
        direction = connection.Direction.ToString(),
        loopback = connection.IsLoopback,
        newObservation = connection.IsNew,
        firstObservedUtc = connection.FirstObservedUtc,
        quality = connection.Quality.ToString(),
        ruleStatus = connection.RuleStatus.ToString(),
        uploadBytesPerSecond = connection.EstimatedUploadBytesPerSecond,
        downloadBytesPerSecond = connection.EstimatedDownloadBytesPerSecond,
    };

    private static object ToHistoryRow(HistoryRow row) => new
    {
        app = row.AppDisplayName,
        path = string.IsNullOrWhiteSpace(row.AppPath) ? null : row.AppPath,
        pid = row.ProcessId,
        protocol = row.Protocol,
        local = row.LocalEndpoint,
        remote = row.RemoteEndpoint,
        direction = row.Direction,
        state = row.State,
        quality = row.Quality,
        firstSeenUtc = row.FirstSeenUtc,
        lastSeenUtc = row.LastSeenUtc,
    };

    private static DateTimeOffset? ParseUtc(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed
            : throw new ArgumentException("Dates must be ISO-8601, for example 2026-11-04T12:00:00Z.");
    }

    internal static string EndpointHost(string endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint) || endpoint == "—")
        {
            return string.Empty;
        }

        var separator = endpoint.LastIndexOf(':');
        return separator > 0 ? endpoint[..separator].Trim('[', ']') : endpoint;
    }

    internal static int? EndpointPort(string endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint) || endpoint == "—")
        {
            return null;
        }

        var separator = endpoint.LastIndexOf(':');
        return separator > 0 && int.TryParse(endpoint[(separator + 1)..], NumberStyles.Integer,
            CultureInfo.InvariantCulture, out var port)
            ? port
            : null;
    }

    internal static bool IsPrivateOrLoopback(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!IPAddress.TryParse(host, out var address))
        {
            return false;
        }

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return bytes[0] == 10 ||
                   (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168) ||
                   (bytes[0] == 169 && bytes[1] == 254) ||
                   (bytes[0] == 100 && bytes[1] is >= 64 and <= 127) ||
                   bytes[0] == 127;
        }

        // IPv6 link-local, site-local, unique-local (fc00::/7) and loopback ::1.
        return address.IsIPv6LinkLocal ||
               address.IsIPv6SiteLocal ||
               (bytes[0] & 0xFE) == 0xFC;
    }

    internal static string InferIndicatorType(string indicator)
    {
        if (indicator.Length == 64 && indicator.All(Uri.IsHexDigit))
        {
            return "sha256";
        }

        return IPAddress.TryParse(indicator, out _) ? "ip" : "domain";
    }
}
