// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Cryptography;
using System.Text;

namespace Axiom.Core.Enforcement;

/// <summary>
/// Bounded, redacted audit entry for one decision. It stores hashes instead of paths, hosts or raw
/// tool arguments so that local logs never become a second copy of user data.
/// </summary>
public sealed record EnforcementAuditEvent
{
    /// <summary>Request identifier; also the idempotency key of the audit log.</summary>
    public required string EventId { get; init; }

    public required DateTimeOffset UtcTime { get; init; }

    /// <summary>SHA-256 prefix of the agent identifier.</summary>
    public required string AgentIdHash { get; init; }

    public required AgentActionKind Kind { get; init; }

    /// <summary>SHA-256 prefix of the target or process path; empty when neither was supplied.</summary>
    public required string TargetHash { get; init; }

    public required string RuleId { get; init; }

    public required string ReasonCode { get; init; }

    public required EnforcementDecision Decision { get; init; }

    public required EnforcementStrength AvailableStrength { get; init; }

    /// <summary>True only when a real boundary could carry out the decision.</summary>
    public required bool CanEnforce { get; init; }
}

/// <summary>One-way hashing for audit fields.</summary>
public static class EnforcementAuditRedactor
{
    /// <summary>Returns a stable 32-character SHA-256 prefix, or an empty string for no value.</summary>
    public static string Hash(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(digest)[..32];
    }
}

/// <summary>Fixed-capacity in-memory audit log with duplicate suppression.</summary>
public sealed class EnforcementAuditLog
{
    public const int DefaultCapacity = 512;

    private readonly int _capacity;
    private readonly Queue<EnforcementAuditEvent> _events = new();
    private readonly HashSet<string> _ids = new(StringComparer.Ordinal);

    public EnforcementAuditLog(int capacity = DefaultCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);

        _capacity = capacity;
    }

    public int Count => _events.Count;

    /// <summary>Oldest-first snapshot; the caller cannot mutate the log through it.</summary>
    public IReadOnlyList<EnforcementAuditEvent> Snapshot() => [.. _events];

    /// <summary>
    /// Adds one entry. Returns false for a repeated event identifier, so a retried hook event does
    /// not duplicate the audit trail.
    /// </summary>
    public bool TryAppend(EnforcementAuditEvent entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (!_ids.Add(entry.EventId))
        {
            return false;
        }

        _events.Enqueue(entry);
        if (_events.Count > _capacity)
        {
            var removed = _events.Dequeue();
            _ids.Remove(removed.EventId);
        }

        return true;
    }

    /// <summary>Builds a redacted entry from a request and the verdict it received.</summary>
    public static EnforcementAuditEvent FromVerdict(
        AgentActionRequest request,
        AgentActionVerdict verdict)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(verdict);

        return new EnforcementAuditEvent
        {
            EventId = request.RequestId,
            UtcTime = request.UtcTime,
            AgentIdHash = EnforcementAuditRedactor.Hash(request.AgentId),
            Kind = request.Kind,
            TargetHash = EnforcementAuditRedactor.Hash(request.Target ?? request.ProcessPath),
            RuleId = verdict.RuleId,
            ReasonCode = verdict.ReasonCode,
            Decision = verdict.Decision,
            AvailableStrength = verdict.AvailableStrength,
            CanEnforce = verdict.CanEnforce,
        };
    }
}
