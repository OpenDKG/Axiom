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
/// Stage E3 prototype broker for mediated file reads. Rejects device/UNC namespaces and
/// symlink/reparse points in the path hierarchy, then opens the file once without following a
/// link in the final component. The policy decision (<see cref="EnforcementPolicyEvaluator"/> at
/// <see cref="EnforcementStrength.TrustedBroker"/>) uses the final path resolved from that handle,
/// the content is read from the same handle, and the file identity (volume + file index, or
/// device + inode) is compared from the handle before and after the read and against what the
/// requested path names afterwards, to detect TOCTOU swaps.
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

        using var handle = BrokerFileHandle.OpenNoFollow(fullPath, out var openFailure);
        if (handle is null)
        {
            return openFailure == BrokerOpenFailure.LinkOrReparse
                ? Deny(BrokerAccessDecision.DeniedReparseOrSymlink, EnforcementReasonCodes.ProtectedResource, requestId, fullPath, "broker-reparse-guard", utcTime)
                : Deny(BrokerAccessDecision.DeniedUnsafePath, EnforcementReasonCodes.InvalidRequest, requestId, fullPath, "broker-no-follow-open", utcTime);
        }

        if (!BrokerFileHandle.TryGetIdentity(handle, out var before))
        {
            return Deny(BrokerAccessDecision.DeniedUnsafePath, EnforcementReasonCodes.InvalidRequest, requestId, fullPath, "broker-no-follow-open", utcTime);
        }

        if (before.IsReparsePoint)
        {
            return Deny(BrokerAccessDecision.DeniedReparseOrSymlink, EnforcementReasonCodes.ProtectedResource, requestId, fullPath, "broker-reparse-guard", utcTime);
        }

        if (!before.IsRegularFile)
        {
            return Deny(BrokerAccessDecision.DeniedUnsafePath, EnforcementReasonCodes.InvalidRequest, requestId, fullPath, "broker-no-follow-open", utcTime);
        }

        // The policy decision binds to the file actually opened, not to the requested string.
        var finalPath = BrokerFileHandle.GetFinalPath(handle, fullPath);
        if (finalPath is null || !TryCanonicalizeLocalPath(finalPath, out finalPath))
        {
            return Deny(BrokerAccessDecision.DeniedUnsafePath, EnforcementReasonCodes.InvalidRequest, requestId, fullPath, "broker-path-canonicalizer", utcTime);
        }

        if (_hasReparsePointInChain(finalPath))
        {
            return Deny(BrokerAccessDecision.DeniedReparseOrSymlink, EnforcementReasonCodes.ProtectedResource, requestId, finalPath, "broker-reparse-guard", utcTime);
        }

        var verdict = _evaluator.Evaluate(
            new AgentActionRequest
            {
                RequestId = requestId,
                AgentId = agentId,
                Kind = AgentActionKind.ReadFile,
                Target = finalPath,
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
                finalPath,
                verdict.Decision,
                EnforcementReceiptResult.OsDenyVerified,
                EnforcementObservedSideEffect.Absent,
                "trusted-file-broker",
                utcTime);
        }

        var bytes = BrokerFileHandle.ReadAll(handle);
        var unchanged = BrokerFileHandle.TryGetIdentity(handle, out var after) && after == before;
        var pathStillNamesFile = false;
        if (unchanged && !_hasReparsePointInChain(fullPath))
        {
            using var current = BrokerFileHandle.OpenNoFollow(fullPath, out _);
            pathStillNamesFile = current is not null &&
                                 BrokerFileHandle.TryGetIdentity(current, out var named) &&
                                 string.Equals(named.FileId, before.FileId, StringComparison.Ordinal);
        }

        if (!unchanged || !pathStillNamesFile)
        {
            return RecordAndReturn(
                BrokerAccessDecision.DeniedToctouMismatch,
                EnforcementReasonCodes.ReplayMismatch,
                requestId,
                finalPath,
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
            finalPath,
            EnforcementDecision.Allow,
            EnforcementReceiptResult.Detected,
            EnforcementObservedSideEffect.Unknown,
            verifiedBy: null,
            utcTime,
            bytes);
    }

    /// <summary>
    /// Final path of <paramref name="path"/> as the broker resolves it from a no-follow handle, so
    /// callers can express policy scopes in the same form the broker evaluates. False when the file
    /// cannot be opened that way.
    /// </summary>
    public static bool TryResolveFinalPath(string path, out string finalPath)
    {
        finalPath = string.Empty;
        if (!TryCanonicalizeLocalPath(path, out var fullPath))
        {
            return false;
        }

        using var handle = BrokerFileHandle.OpenNoFollow(fullPath, out _);
        var resolved = handle is null ? null : BrokerFileHandle.GetFinalPath(handle, fullPath);
        return resolved is not null && TryCanonicalizeLocalPath(resolved, out finalPath);
    }

    private BrokerFileOpenResult Deny(
        BrokerAccessDecision decision,
        string reasonCode,
        string requestId,
        string target,
        string verifiedBy,
        DateTimeOffset utcTime) =>
        RecordAndReturn(
            decision,
            reasonCode,
            requestId,
            target,
            EnforcementDecision.Block,
            EnforcementReceiptResult.OsDenyVerified,
            EnforcementObservedSideEffect.Absent,
            verifiedBy,
            utcTime);

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
}
