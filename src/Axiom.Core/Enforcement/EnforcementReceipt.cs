// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Cryptography;
using System.Text;

namespace Axiom.Core.Enforcement;

/// <summary>Honest outcome classification defined by Handoff v2.0 §4.3.</summary>
public enum EnforcementReceiptResult
{
    Detected = 0,
    GuardUnavailable = 1,
    AuditOnly = 2,
    DenyRequested = 3,
    HostDenySent = 4,
    HostDenyVerified = 5,
    OsDenyVerified = 6,
    Unverified = 7,
    FailedOpen = 8,
}

/// <summary>Whether an actual side effect on a protected or canary target was observed.</summary>
public enum EnforcementObservedSideEffect
{
    Unknown = 0,
    Absent = 1,
    Present = 2,
}

/// <summary>Enforcement boundary that processed the action.</summary>
public enum EnforcementBoundaryKind
{
    None = 0,
    DetectorOnly = 1,
    HostHook = 2,
    TrustedBroker = 3,
    OsFirewall = 4,
}

/// <summary>Canonical wire/log string tokens for receipt fields.</summary>
public static class EnforcementReceiptTokens
{
    public static string ToResultToken(EnforcementReceiptResult result) => result switch
    {
        EnforcementReceiptResult.Detected => "DETECTED",
        EnforcementReceiptResult.GuardUnavailable => "GUARD_UNAVAILABLE",
        EnforcementReceiptResult.AuditOnly => "AUDIT_ONLY",
        EnforcementReceiptResult.DenyRequested => "DENY_REQUESTED",
        EnforcementReceiptResult.HostDenySent => "HOST_DENY_SENT",
        EnforcementReceiptResult.HostDenyVerified => "HOST_DENY_VERIFIED",
        EnforcementReceiptResult.OsDenyVerified => "OS_DENY_VERIFIED",
        EnforcementReceiptResult.Unverified => "UNVERIFIED",
        EnforcementReceiptResult.FailedOpen => "FAILED_OPEN",
        _ => "UNVERIFIED",
    };

    public static bool TryParseResultToken(string? token, out EnforcementReceiptResult result)
    {
        result = token?.Trim().ToUpperInvariant() switch
        {
            "DETECTED" => EnforcementReceiptResult.Detected,
            "GUARD_UNAVAILABLE" => EnforcementReceiptResult.GuardUnavailable,
            "AUDIT_ONLY" => EnforcementReceiptResult.AuditOnly,
            "DENY_REQUESTED" => EnforcementReceiptResult.DenyRequested,
            "HOST_DENY_SENT" => EnforcementReceiptResult.HostDenySent,
            "HOST_DENY_VERIFIED" => EnforcementReceiptResult.HostDenyVerified,
            "OS_DENY_VERIFIED" => EnforcementReceiptResult.OsDenyVerified,
            "UNVERIFIED" => EnforcementReceiptResult.Unverified,
            "FAILED_OPEN" => EnforcementReceiptResult.FailedOpen,
            _ => (EnforcementReceiptResult)(-1),
        };
        return Enum.IsDefined(result);
    }

    public static string ToSideEffectToken(EnforcementObservedSideEffect sideEffect) => sideEffect switch
    {
        EnforcementObservedSideEffect.Absent => "absent",
        EnforcementObservedSideEffect.Present => "present",
        _ => "unknown",
    };

    public static string ToBoundaryToken(EnforcementBoundaryKind boundary) => boundary switch
    {
        EnforcementBoundaryKind.DetectorOnly => "detector_only",
        EnforcementBoundaryKind.HostHook => "host_hook",
        EnforcementBoundaryKind.TrustedBroker => "trusted_broker",
        EnforcementBoundaryKind.OsFirewall => "os_firewall",
        _ => "none",
    };
}

/// <summary>
/// Redacted, tamper-evident enforcement receipt (<c>axiom.enforcement.receipt.v1</c>). Raw file
/// paths, secrets, prompts, and command bodies are never stored.
/// </summary>
public sealed record EnforcementReceiptV1
{
    public const string SchemaVersion = "axiom.enforcement.receipt.v1";

    public string Schema { get; init; } = SchemaVersion;

    public required string EventId { get; init; }

    public required string RequestId { get; init; }

    public required string PolicyRevision { get; init; }

    public required string HostAdapter { get; init; }

    public string HostVersion { get; init; } = "unknown";

    public required AgentActionKind ActionKind { get; init; }

    public required string DecisionSource { get; init; }

    /// <summary>Redacted SHA-256 prefix of target/indicator; never raw paths or secrets.</summary>
    public string IndicatorRef { get; init; } = string.Empty;

    public required EnforcementDecision RequestedDecision { get; init; }

    public required EnforcementBoundaryKind Boundary { get; init; }

    public required EnforcementReceiptResult Result { get; init; }

    public EnforcementObservedSideEffect ObservedSideEffect { get; init; } =
        EnforcementObservedSideEffect.Unknown;

    public string? VerifiedBy { get; init; }

    public DateTimeOffset TimestampUtc { get; init; }

    public string PreviousHash { get; init; } = string.Empty;

    public string IntegrityHash { get; init; } = string.Empty;

    public string ResultToken => EnforcementReceiptTokens.ToResultToken(Result);

    /// <summary>
    /// Creates a redacted receipt and enforces the anti-overclaim invariant:
    /// <see cref="EnforcementReceiptResult.HostDenyVerified"/> and
    /// <see cref="EnforcementReceiptResult.OsDenyVerified"/> require
    /// <see cref="EnforcementObservedSideEffect.Absent"/> and a non-empty <paramref name="verifiedBy"/>;
    /// otherwise the result is downgraded to <see cref="EnforcementReceiptResult.Unverified"/>.
    /// </summary>
    public static EnforcementReceiptV1 Create(
        string eventId,
        string requestId,
        string? policyRevision,
        string hostAdapter,
        string? hostVersion,
        AgentActionKind actionKind,
        string decisionSource,
        string? rawTargetOrIndicator,
        EnforcementDecision requestedDecision,
        EnforcementBoundaryKind boundary,
        EnforcementReceiptResult result,
        EnforcementObservedSideEffect observedSideEffect,
        string? verifiedBy,
        DateTimeOffset timestampUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventId);
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);
        ArgumentException.ThrowIfNullOrWhiteSpace(hostAdapter);
        ArgumentException.ThrowIfNullOrWhiteSpace(decisionSource);

        var safeVerifiedBy = string.IsNullOrWhiteSpace(verifiedBy) ? null : verifiedBy.Trim();
        var effectiveResult = EnforceVerifiedInvariant(result, observedSideEffect, safeVerifiedBy);

        return new EnforcementReceiptV1
        {
            Schema = SchemaVersion,
            EventId = eventId.Trim(),
            RequestId = requestId.Trim(),
            PolicyRevision = string.IsNullOrWhiteSpace(policyRevision) ? "0" : policyRevision.Trim(),
            HostAdapter = hostAdapter.Trim(),
            HostVersion = string.IsNullOrWhiteSpace(hostVersion) ? "unknown" : hostVersion.Trim(),
            ActionKind = actionKind,
            DecisionSource = decisionSource.Trim(),
            IndicatorRef = EnforcementAuditRedactor.Hash(rawTargetOrIndicator),
            RequestedDecision = requestedDecision,
            Boundary = boundary,
            Result = effectiveResult,
            ObservedSideEffect = observedSideEffect,
            VerifiedBy = effectiveResult is EnforcementReceiptResult.HostDenyVerified
                or EnforcementReceiptResult.OsDenyVerified
                ? safeVerifiedBy
                : null,
            TimestampUtc = timestampUtc,
        };
    }

    public static string ComputePolicyRevisionHash(string? rawPolicyContent)
    {
        if (string.IsNullOrEmpty(rawPolicyContent))
        {
            return "0";
        }

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(rawPolicyContent));
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    private static EnforcementReceiptResult EnforceVerifiedInvariant(
        EnforcementReceiptResult requested,
        EnforcementObservedSideEffect sideEffect,
        string? verifiedBy)
    {
        if (requested is EnforcementReceiptResult.HostDenyVerified or EnforcementReceiptResult.OsDenyVerified)
        {
            return sideEffect == EnforcementObservedSideEffect.Absent && verifiedBy is not null
                ? requested
                : EnforcementReceiptResult.Unverified;
        }

        return requested;
    }
}

/// <summary>Aggregated summary over the active receipt journal window.</summary>
public sealed record EnforcementReceiptSummary
{
    public int Total { get; init; }

    public int Detected { get; init; }

    public int GuardUnavailable { get; init; }

    public int AuditOnly { get; init; }

    public int DenyRequested { get; init; }

    public int HostDenySent { get; init; }

    public int HostDenyVerified { get; init; }

    public int OsDenyVerified { get; init; }

    public int Unverified { get; init; }

    public int FailedOpen { get; init; }

    public bool ChainValid { get; init; } = true;

    public string? LatestResultToken { get; init; }

    public DateTimeOffset? LatestTimestampUtc { get; init; }
}

/// <summary>
/// Thread-safe, fixed-capacity, hash-chained enforcement receipt journal with duplicate suppression
/// by <see cref="EnforcementReceiptV1.EventId"/>.
/// </summary>
public sealed class EnforcementReceiptJournal
{
    public const int DefaultCapacity = 512;

    private readonly int _capacity;
    private readonly object _gate = new();
    private readonly Queue<EnforcementReceiptV1> _entries = new();
    private readonly HashSet<string> _eventIds = new(StringComparer.Ordinal);
    private string _tailHash = string.Empty;

    public EnforcementReceiptJournal(int capacity = DefaultCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        _capacity = capacity;
    }

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }

    public bool TryAppend(EnforcementReceiptV1 receipt, out EnforcementReceiptV1? recorded)
    {
        ArgumentNullException.ThrowIfNull(receipt);

        lock (_gate)
        {
            if (!_eventIds.Add(receipt.EventId))
            {
                recorded = null;
                return false;
            }

            var previousHash = _tailHash;
            var chained = receipt with
            {
                PreviousHash = previousHash,
                IntegrityHash = ComputeIntegrityHash(receipt, previousHash),
            };

            _entries.Enqueue(chained);
            _tailHash = chained.IntegrityHash;

            if (_entries.Count > _capacity)
            {
                var evicted = _entries.Dequeue();
                _eventIds.Remove(evicted.EventId);
            }

            recorded = chained;
            return true;
        }
    }

    public bool TryAppend(EnforcementReceiptV1 receipt) => TryAppend(receipt, out _);

    public IReadOnlyList<EnforcementReceiptV1> Snapshot()
    {
        lock (_gate)
        {
            return [.. _entries];
        }
    }

    /// <summary>
    /// Verifies that every contiguous receipt in the current window has an unbroken integrity hash.
    /// </summary>
    public bool VerifyChain()
    {
        var items = Snapshot();
        if (items.Count == 0)
        {
            return true;
        }

        for (var i = 0; i < items.Count; i++)
        {
            var entry = items[i];
            if (i > 0 && !string.Equals(entry.PreviousHash, items[i - 1].IntegrityHash, StringComparison.Ordinal))
            {
                return false;
            }

            var expected = ComputeIntegrityHash(entry, entry.PreviousHash);
            if (!string.Equals(entry.IntegrityHash, expected, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    public EnforcementReceiptSummary Summarize()
    {
        var items = Snapshot();
        var chainValid = VerifyChain();

        int detected = 0, guardUnavailable = 0, auditOnly = 0, denyRequested = 0;
        int hostDenySent = 0, hostDenyVerified = 0, osDenyVerified = 0, unverified = 0, failedOpen = 0;

        foreach (var item in items)
        {
            switch (item.Result)
            {
                case EnforcementReceiptResult.Detected:
                    detected++;
                    break;
                case EnforcementReceiptResult.GuardUnavailable:
                    guardUnavailable++;
                    break;
                case EnforcementReceiptResult.AuditOnly:
                    auditOnly++;
                    break;
                case EnforcementReceiptResult.DenyRequested:
                    denyRequested++;
                    break;
                case EnforcementReceiptResult.HostDenySent:
                    hostDenySent++;
                    break;
                case EnforcementReceiptResult.HostDenyVerified:
                    hostDenyVerified++;
                    break;
                case EnforcementReceiptResult.OsDenyVerified:
                    osDenyVerified++;
                    break;
                case EnforcementReceiptResult.Unverified:
                    unverified++;
                    break;
                case EnforcementReceiptResult.FailedOpen:
                    failedOpen++;
                    break;
            }
        }

        var latest = items.Count > 0 ? items[^1] : null;
        return new EnforcementReceiptSummary
        {
            Total = items.Count,
            Detected = detected,
            GuardUnavailable = guardUnavailable,
            AuditOnly = auditOnly,
            DenyRequested = denyRequested,
            HostDenySent = hostDenySent,
            HostDenyVerified = hostDenyVerified,
            OsDenyVerified = osDenyVerified,
            Unverified = unverified,
            FailedOpen = failedOpen,
            ChainValid = chainValid,
            LatestResultToken = latest?.ResultToken,
            LatestTimestampUtc = latest?.TimestampUtc,
        };
    }

    private static string ComputeIntegrityHash(EnforcementReceiptV1 receipt, string previousHash)
    {
        var canonical = string.Join(
            '|',
            receipt.Schema,
            receipt.EventId,
            receipt.RequestId,
            receipt.PolicyRevision,
            receipt.HostAdapter,
            receipt.HostVersion,
            receipt.ActionKind.ToString(),
            receipt.DecisionSource,
            receipt.IndicatorRef,
            receipt.RequestedDecision.ToString(),
            EnforcementReceiptTokens.ToBoundaryToken(receipt.Boundary),
            receipt.ResultToken,
            EnforcementReceiptTokens.ToSideEffectToken(receipt.ObservedSideEffect),
            receipt.VerifiedBy ?? string.Empty,
            receipt.TimestampUtc.UtcTicks.ToString(System.Globalization.CultureInfo.InvariantCulture),
            previousHash);

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(digest).ToLowerInvariant();
    }
}
