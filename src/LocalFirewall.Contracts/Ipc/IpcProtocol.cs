// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LocalFirewall.Contracts.Ipc;

/// <summary>Protocol versioning and hard limits shared by client and service.</summary>
public static class IpcProtocol
{
    public const int CurrentVersion = 1;

    public const int MinimumSupportedVersion = 1;

    /// <summary>Maximum accepted request size. Enforced before deserialisation.</summary>
    public const int MaxMessageBytes = 256 * 1024;

    /// <summary>
    /// Maximum accepted response size. A snapshot with thousands of sockets legitimately exceeds
    /// the request limit, so responses have a separate, larger cap.
    /// </summary>
    public const int MaxResponseBytes = 4 * 1024 * 1024;

    public static bool IsSupported(int version) =>
        version >= MinimumSupportedVersion && version <= CurrentVersion;
}

/// <summary>Command names accepted on the pipe. No generic shell or exec command exists.</summary>
public static class IpcCommandTypes
{
    public const string Capabilities = "capabilities";
    public const string ServiceHealth = "serviceHealth";
    public const string Snapshot = "snapshot";
    public const string LiveEvents = "live.events";
    public const string RuleApply = "rule.apply";
    public const string RuleRemove = "rule.remove";
    public const string RuleVerify = "rule.verify";
    public const string HistoryQuery = "history.query";
    public const string ConfigGet = "config.get";
    public const string ConfigSet = "config.set";
    public const string DiagnosticsExport = "diagnostics.export";

    public static IReadOnlyList<string> All { get; } =
    [
        Capabilities,
        ServiceHealth,
        Snapshot,
        LiveEvents,
        RuleApply,
        RuleRemove,
        RuleVerify,
        HistoryQuery,
        ConfigGet,
        ConfigSet,
        DiagnosticsExport,
    ];
}

public sealed record IpcError(string Code, string Message);

public sealed record IpcResponse
{
    public required Guid Id { get; init; }

    public required bool Ok { get; init; }

    public JsonElement? Result { get; init; }

    public IpcError? Error { get; init; }

    public long? CurrentRevision { get; init; }
}

public static class IpcJson
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        AllowTrailingCommas = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 8,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };
}
