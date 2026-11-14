// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Cryptography;

namespace Axiom.Core.Enforcement;

/// <summary>Outcome of a trusted file broker mediation check (Stage E3).</summary>
public enum BrokerAccessDecision
{
    Allowed = 0,
    DeniedByPolicy = 1,
    DeniedUnsafePath = 2,
    DeniedReparseOrSymlink = 3,
    DeniedToctouMismatch = 4,
}

/// <summary>Result of mediating a file read through <see cref="TrustedFileBroker"/>.</summary>
public sealed record BrokerFileOpenResult(
    BrokerAccessDecision Decision,
    string ReasonCode,
    EnforcementReceiptV1 Receipt,
    byte[]? ContentBytes = null);

/// <summary>
/// Stage E3 prototype broker for mediated file reads. Rejects device/UNC namespaces, rejects
/// symlink/reparse points in the path hierarchy, enforces <see cref="EnforcementPolicyEvaluator"/>
/// at <see cref="EnforcementStrength.TrustedBroker"/>, and compares file identity before and after
/// reading to detect TOCTOU swaps.
/// </summary>
public sealed class TrustedFileBroker(
    EnforcementPolicyEvaluator evaluator,
    Func<string, bool>? hasReparsePointInChain = null,
    EnforcementReceiptJournal? journal = null,
    string policyRevision = "0")
{
    private readonly EnforcementPolicyEvaluator _evaluator =
        evaluator ?? throw new ArgumentNullException(nameof(evaluator));

    private readonly Func<string, bool> _hasReparsePointInChain =
        hasReparsePointInChain ?? DefaultHasReparsePoint;

    private readonly EnforcementReceiptJournal? _journal = journal;
    private readonly string _policyRevision = string.IsNullOrWhiteSpace(policyRevision) ? "0" : policyRevision;

    /// <summary>Validates path syntax, rejects device/UNC namespaces, and returns canonical full path.</summary>
    public static bool TryCanonicalizeLocalPath(string? rawPath, out string canonicalPath)
    {
        canonicalPath = string.Empty;
        if (string.IsNullOrWhiteSpace(rawPath) || rawPath.Length > EnforcementPolicyEvaluator.MaximumTargetLength)
        {
            return false;
        }

        var trimmed = rawPath.Trim();
        if (trimmed.Any(char.IsControl) ||
            trimmed.StartsWith(@"\\", StringComparison.Ordinal) ||
            trimmed.StartsWith("//", StringComparison.Ordinal))
        {
            return false;
        }

        if (!Path.IsPathFullyQualified(trimmed))
        {
            return false;
        }

        try
        {
            canonicalPath = Path.GetFullPath(trimmed);
            return !canonicalPath.StartsWith(@"\\", StringComparison.Ordinal);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    public BrokerFileOpenResult OpenRead(
        string agentId,
        string requestId,
        string? requestedPath,
        DateTimeOffset utcTime)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);

        if (!TryCanonicalizeLocalPath(requestedPath, out var fullPath))
        {
            return RecordAndReturn(
                BrokerAccessDecision.DeniedUnsafePath,
                EnforcementReasonCodes.InvalidRequest,
                requestId,
                requestedPath,
                EnforcementDecision.Block,
                EnforcementReceiptResult.OsDenyVerified,
                EnforcementObservedSideEffect.Absent,
                "broker-path-canonicalizer",
                utcTime);
        }

        if (_hasReparsePointInChain(fullPath))
        {
            return RecordAndReturn(
                BrokerAccessDecision.DeniedReparseOrSymlink,
                EnforcementReasonCodes.ProtectedResource,
                requestId,
                fullPath,
                EnforcementDecision.Block,
                EnforcementReceiptResult.OsDenyVerified,
                EnforcementObservedSideEffect.Absent,
                "broker-reparse-guard",
                utcTime);
        }

        var verdict = _evaluator.Evaluate(
            new AgentActionRequest
            {
                RequestId = requestId,
                AgentId = agentId,
                Kind = AgentActionKind.ReadFile,
                Target = fullPath,
                UtcTime = utcTime,
            },
            new EnforcementCapabilities
            {
                Strength = EnforcementStrength.TrustedBroker,
                HostSupportsDeny = true,
            });

        if (verdict.Decision != EnforcementDecision.Allow)
        {
            return RecordAndReturn(
                BrokerAccessDecision.DeniedByPolicy,
                verdict.ReasonCode,
                requestId,
                fullPath,
                verdict.Decision,
                EnforcementReceiptResult.OsDenyVerified,
                EnforcementObservedSideEffect.Absent,
                "trusted-file-broker",
                utcTime);
        }

        var beforeStamp = CaptureFileStamp(fullPath);
        var bytes = File.ReadAllBytes(fullPath);
        var afterStamp = CaptureFileStamp(fullPath);

        if (_hasReparsePointInChain(fullPath) || !string.Equals(beforeStamp, afterStamp, StringComparison.Ordinal))
        {
            return RecordAndReturn(
                BrokerAccessDecision.DeniedToctouMismatch,
                EnforcementReasonCodes.ReplayMismatch,
                requestId,
                fullPath,
                EnforcementDecision.Block,
                EnforcementReceiptResult.OsDenyVerified,
                EnforcementObservedSideEffect.Absent,
                "broker-toctou-guard",
                utcTime);
        }

        return RecordAndReturn(
            BrokerAccessDecision.Allowed,
            verdict.ReasonCode,
            requestId,
            fullPath,
            EnforcementDecision.Allow,
            EnforcementReceiptResult.Detected,
            EnforcementObservedSideEffect.Unknown,
            verifiedBy: null,
            utcTime,
            bytes);
    }

    private BrokerFileOpenResult RecordAndReturn(
        BrokerAccessDecision decision,
        string reasonCode,
        string requestId,
        string? rawTarget,
        EnforcementDecision requestedDecision,
        EnforcementReceiptResult receiptResult,
        EnforcementObservedSideEffect sideEffect,
        string? verifiedBy,
        DateTimeOffset utcTime,
        byte[]? bytes = null)
    {
        var receipt = EnforcementReceiptV1.Create(
            eventId: $"{requestId}:broker:{decision}",
            requestId: requestId,
            policyRevision: _policyRevision,
            hostAdapter: "trusted-file-broker",
            hostVersion: "e3-prototype",
            actionKind: AgentActionKind.ReadFile,
            decisionSource: reasonCode,
            rawTargetOrIndicator: rawTarget,
            requestedDecision: requestedDecision,
            boundary: EnforcementBoundaryKind.TrustedBroker,
            result: receiptResult,
            observedSideEffect: sideEffect,
            verifiedBy: verifiedBy,
            timestampUtc: utcTime);

        _journal?.TryAppend(receipt);
        return new BrokerFileOpenResult(decision, reasonCode, receipt, bytes);
    }

    private static bool DefaultHasReparsePoint(string fullPath)
    {
        var current = fullPath;
        while (!string.IsNullOrEmpty(current))
        {
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                return true;
            }

            current = Path.GetDirectoryName(current);
        }

        return false;
    }

    private static string CaptureFileStamp(string fullPath)
    {
        if (!File.Exists(fullPath))
        {
            return "missing";
        }

        var info = new FileInfo(fullPath);
        return string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{info.Length}|{info.CreationTimeUtc.Ticks}|{info.LastWriteTimeUtc.Ticks}");
    }
}
