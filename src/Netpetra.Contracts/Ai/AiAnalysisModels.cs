// SPDX-License-Identifier: GPL-3.0-or-later
namespace Netpetra.Contracts.Ai;

public enum AiProviderKind
{
    OpenAiCompatible = 0,
    LocalOpenAiCompatible = 1,
}

public sealed record AiAnalystSettings
{
    public bool Enabled { get; init; }

    public AiProviderKind Provider { get; init; } = AiProviderKind.OpenAiCompatible;

    public string Endpoint { get; init; } = string.Empty;

    public string Model { get; init; } = string.Empty;

    /// <summary>Redacts local paths to file names before any external request.</summary>
    public bool RedactPaths { get; init; } = true;

    public int MaxConnections { get; init; } = 25;

    public int MaxTokens { get; init; } = 1200;

    public bool AutomaticAnalysis { get; init; }

    public int AnalysisIntervalMinutes { get; init; } = 15;

    public int MaxRequestsPerHour { get; init; } = 6;

    /// <summary>Optional second model used to challenge the primary result with a separate context.</summary>
    public string VerifierModel { get; init; } = string.Empty;
}

/// <summary>
/// Structured analyst result. Recommendations are text only; this type has no firewall or shell
/// action fields by design.
/// </summary>
public sealed record AiFinding
{
    public string FindingId { get; init; } = Guid.NewGuid().ToString("N");

    public string Status { get; init; } = "INSUFFICIENT_DATA";

    public string Severity { get; init; } = "unknown";

    public string Confidence { get; init; } = "none";

    public string Summary { get; init; } = "No analysis has run.";

    public IReadOnlyList<string> Observations { get; init; } = [];

    public IReadOnlyList<string> EvidenceReferences { get; init; } = [];

    public IReadOnlyList<string> AlternativeExplanations { get; init; } = [];

    public IReadOnlyList<string> MissingEvidence { get; init; } = [];

    public IReadOnlyList<string> RecommendedActions { get; init; } = [];

    public string Model { get; init; } = string.Empty;

    public DateTimeOffset AnalysisTimestampUtc { get; init; } = DateTimeOffset.UtcNow;

    public bool HumanReviewed { get; init; }

    public string VerifierModel { get; init; } = string.Empty;

    public string VerifierStatus { get; init; } = "not run";

    public string VerifierSummary { get; init; } = string.Empty;

    public string? Error { get; init; }
}

public sealed record AiEvidencePackage(
    string SchemaVersion,
    DateTimeOffset CapturedUtc,
    string SourceName,
    string PrivacyMode,
    IReadOnlyList<string> Limitations,
    IReadOnlyList<AiEvidenceConnection> Connections);

public sealed record AiEvidenceConnection(
    string Reference,
    string Application,
    string? Path,
    int ProcessId,
    string Protocol,
    string Direction,
    string State,
    string LocalEndpoint,
    string RemoteEndpoint,
    bool IsLoopback,
    bool IsNew,
    DateTimeOffset FirstObservedUtc,
    string Quality);
