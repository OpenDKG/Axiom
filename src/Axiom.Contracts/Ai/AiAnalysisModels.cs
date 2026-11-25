// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json.Serialization;

namespace Axiom.Contracts.Ai;

public enum AiProviderKind
{
    OpenAiCompatible = 0,
    LocalOpenAiCompatible = 1,
    OpenAi = 2,
    Anthropic = 3,
    DeepSeek = 4,
    Zai = 5,
    OpenCodeZen = 6,
    OpenChamberLocal = 7,
    GoogleGemini = 8,
    OpenRouter = 9,
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

    /// <summary>
    /// Values the model wants treated as malicious. Only structured entries are considered for
    /// sharing, and only when Axiom observed the same value itself; prose is never scanned.
    /// </summary>
    public IReadOnlyList<AiIndicator> Indicators { get; init; } = [];

    public string Model { get; init; } = string.Empty;

    public DateTimeOffset AnalysisTimestampUtc { get; init; } = DateTimeOffset.UtcNow;

    public bool HumanReviewed { get; init; }

    public string VerifierModel { get; init; } = string.Empty;

    public string VerifierStatus { get; init; } = "not run";

    public string VerifierSummary { get; init; } = string.Empty;

    public string? Error { get; init; }

    [JsonIgnore]
    public AiFindingAssessment Assessment
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(Error))
            {
                return AiFindingAssessment.Failed;
            }

            return (Status?.Trim().ToUpperInvariant(), Severity?.Trim().ToLowerInvariant()) switch
            {
                ("SUSPICIOUS" or "SUPPORTED_ALERT", "high" or "critical") => AiFindingAssessment.Serious,
                ("SUSPICIOUS" or "SUPPORTED_ALERT", _) => AiFindingAssessment.Flagged,
                ("LOW_OBSERVED_RISK", "low") => AiFindingAssessment.LowRisk,
                _ => AiFindingAssessment.Uncertain,
            };
        }
    }
}

/// <summary>Display labels and colors derived from a finding's status and severity.</summary>
public sealed record AiFindingAssessment(string Label, bool IsSerious = false, bool IsFlagged = false, bool IsLowRisk = false)
{
    internal static AiFindingAssessment Serious { get; } = new("High-priority finding", IsSerious: true);
    internal static AiFindingAssessment Flagged { get; } = new("Flagged for review", IsFlagged: true);
    internal static AiFindingAssessment LowRisk { get; } = new("Low observed risk", IsLowRisk: true);
    internal static AiFindingAssessment Uncertain { get; } = new("Inconclusive");
    internal static AiFindingAssessment Failed { get; } = new("Analysis failed");
}

/// <summary>
/// One structured indicator proposed by the model. <see cref="Role"/> is "malicious", "suspicious"
/// or "unknown"; only "malicious" entries are ever considered for sharing.
/// </summary>
public sealed record AiIndicator
{
    public string Type { get; init; } = string.Empty;

    public string Value { get; init; } = string.Empty;

    public string Role { get; init; } = "unknown";

    /// <summary>
    /// Optional closed Blackbox reason code (for example "malware-delivery", "phishing",
    /// "command-and-control", "credential-harvest", "exfil-endpoint", "scam", "injection-host"),
    /// or "unknown" when evidence does not establish a specific threat reason.
    /// </summary>
    public string Reason { get; init; } = string.Empty;
}

public sealed record AiEvidencePackage(
    string SchemaVersion,
    DateTimeOffset CapturedUtc,
    string SourceName,
    string PrivacyMode,
    IReadOnlyList<string> Limitations,
    IReadOnlyList<AiEvidenceConnection> Connections)
{
    /// <summary>Local host context that helps the analyst interpret private and public endpoints.</summary>
    public AiEvidenceHostContext? Host { get; init; }

    /// <summary>Number of days covered by the local flow baseline, or 0 when unavailable.</summary>
    public int BaselineWindowDays { get; init; }

    public int BaselineRowsConsidered { get; init; }

    public int BaselineTotalCount { get; init; }

    public bool BaselineTruncated { get; init; }

    public string BaselineNote { get; init; } = string.Empty;
}

public sealed record AiEvidenceHostContext(
    IReadOnlyList<string> LocalAddresses,
    IReadOnlyList<string> SubnetPrefixes,
    IReadOnlyList<string> Gateways,
    string DnsSuffix,
    string Note);

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
    string Quality)
{
    /// <summary>Parent process resolved from the Windows process snapshot.</summary>
    public int? ParentProcessId { get; init; }

    public string ParentProcessName { get; init; } = string.Empty;

    /// <summary>Immediate parent chain, oldest last, for example "node.exe (18612) &lt;- code.exe (9000)".</summary>
    public string ParentChain { get; init; } = string.Empty;

    /// <summary>Authenticode signer subject, or empty when the image is unsigned/unreadable.</summary>
    public string SignerName { get; init; } = string.Empty;

    public string ProductName { get; init; } = string.Empty;

    public string FileVersion { get; init; } = string.Empty;

    public bool? IsSigned { get; init; }

    /// <summary>Valid, Untrusted, Unsigned or Unavailable.</summary>
    public string SignatureStatus { get; init; } = string.Empty;

    /// <summary>Sanitised command line from the elevated service, when available.</summary>
    public string CommandLine { get; init; } = string.Empty;

    /// <summary>Windows service names hosted by this process, usually only for svchost.exe.</summary>
    public string HostedServices { get; init; } = string.Empty;

    /// <summary>Windows service names hosted by the immediate parent, when it is svchost.exe.</summary>
    public string ParentHostedServices { get; init; } = string.Empty;

    /// <summary>Why the process attribution is complete, unowned or unavailable.</summary>
    public string Ownership { get; init; } = string.Empty;

    /// <summary>Time since Axiom first observed this flow, not the OS TCP start time.</summary>
    public int ObservedDurationSeconds { get; init; }

    /// <summary>Well-known service name for the remote port, when known.</summary>
    public string RemotePortService { get; init; } = string.Empty;

    public string RuleStatus { get; init; } = string.Empty;

    /// <summary>Rows in the 30-day local history for this exact app/protocol/remote/direction.</summary>
    public int? BaselineFlowRows { get; init; }

    public DateTimeOffset? BaselineFirstSeenUtc { get; init; }

    public DateTimeOffset? BaselineLastSeenUtc { get; init; }

    /// <summary>Rows in the 30-day local history for this application, across remote endpoints.</summary>
    public int? BaselineAppFlowRows { get; init; }

    /// <summary>Most frequent remote endpoints for this application in the local history.</summary>
    public IReadOnlyList<string> BaselineTypicalRemotes { get; init; } = [];
}
