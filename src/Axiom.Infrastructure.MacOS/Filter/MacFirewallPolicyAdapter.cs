// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Axiom.Core.Protection;

namespace Axiom.Infrastructure.MacOS.Filter;

/// <summary>
/// macOS firewall adapter. The "OS firewall" is the AxiomFilter system extension, which enforces
/// the table the daemon publishes to <c>filter/rules.json</c>. The adapter owns
/// <c>filter/managed-rules.json</c> (its durable record of Axiom-owned rules, the equivalent of the
/// Axiom-named Windows Firewall rules) and republishes rules.json atomically with a new generation
/// after every change. Writes require the same gate as Windows (<see cref="FirewallWriteGate"/>).
/// Publishing is not enforcing (review 2026-11-12 P0 #2/#3): a rule is <see cref="RuleState.Applied"/>
/// only once <see cref="FilterStatus"/> proves the extension is connected and acknowledged the
/// published generation without rejecting the file or the rule; until then it is
/// <see cref="RuleState.Pending"/>, and a rejection is <see cref="RuleState.Failed"/> with the
/// filter's reason. The same conditions gate <see cref="Verify"/>'s effective action.
/// </summary>
public sealed class MacFirewallPolicyAdapter : IFirewallPolicyAdapter, IOwnedRuleRecoveryAdapter, IDisposable
{
    private static readonly JsonSerializerOptions StateJson = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly MacServicePaths _paths;

    private readonly FilterStatus _status;

    private readonly Func<bool> _writeGate;

    private readonly TimeProvider _time;

    private readonly SemaphoreSlim _gate = new(1, 1);

    private readonly TimeSpan _ackTimeout;

    /// <summary>
    /// How long a write waits for the extension's <c>filter.rules</c> acknowledgement before
    /// answering <see cref="RuleState.Pending"/>. The filter reloads within about 50 ms; the
    /// bound keeps a stalled extension from blocking the IPC caller.
    /// </summary>
    public static readonly TimeSpan DefaultAckTimeout = TimeSpan.FromSeconds(2);

    public MacFirewallPolicyAdapter(MacServicePaths paths, FilterStatus status)
        : this(paths, status, () => FirewallWriteGate.IsOpen, TimeProvider.System, DefaultAckTimeout)
    {
    }

    public MacFirewallPolicyAdapter(
        MacServicePaths paths,
        FilterStatus status,
        Func<bool> writeGate,
        TimeProvider time)
        : this(paths, status, writeGate, time, DefaultAckTimeout)
    {
    }

    public MacFirewallPolicyAdapter(
        MacServicePaths paths,
        FilterStatus status,
        Func<bool> writeGate,
        TimeProvider time,
        TimeSpan ackTimeout)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _status = status ?? throw new ArgumentNullException(nameof(status));
        _writeGate = writeGate ?? throw new ArgumentNullException(nameof(writeGate));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _ackTimeout = ackTimeout < TimeSpan.Zero ? TimeSpan.Zero : ackTimeout;
    }

    public void Dispose() => _gate.Dispose();

    public Task<FirewallCapabilityReport> GetCapabilitiesAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var now = _time.GetUtcNow();

        if (!TryProbeWritable(out var problem))
        {
            return Task.FromResult(new FirewallCapabilityReport
            {
                Status = FirewallCapabilityStatus.Unavailable,
                Reason = $"The AxiomFilter rule table {_paths.RulesFile} is not writable ({problem}). " +
                         "Firewall rules need the root axiomd launchd daemon.",
                FirewallServiceRunning = _status.IsConnected,
                ManagedRulesReadable = false,
                ManagedRuleCount = null,
                ProbedUtc = now,
            });
        }

        var state = LoadState();
        var enforcement = _status.Snapshot(state.Generation);
        var reason = enforcement.State switch
        {
            FilterEnforcementState.Unavailable =>
                "The AxiomFilter network extension has not connected to " +
                $"{_paths.FilterSocketPath}; rules are written to {_paths.RulesFile} " +
                "but are not enforced until the extension is activated.",
            FilterEnforcementState.Degraded =>
                "The AxiomFilter network extension is disconnected (last seen " + Utc(enforcement.LastSeenUtc) + "); " +
                "published rules are not known to be enforced.",
            FilterEnforcementState.Pending when enforcement.Rules is { IsError: true } rejected =>
                "AxiomFilter rejected the rules file (" + rejected.Error + "); generation " +
                rejected.Generation.ToString(CultureInfo.InvariantCulture) + " stays in force and rules generation " +
                state.Generation.ToString(CultureInfo.InvariantCulture) + " is not verified.",
            FilterEnforcementState.Pending =>
                "AxiomFilter has not acknowledged rules generation " + state.Generation.ToString(CultureInfo.InvariantCulture) + " yet" +
                (enforcement.AckedGeneration is { } acked ? " (last acknowledged " + acked.ToString(CultureInfo.InvariantCulture) + ")" : string.Empty) + ".",
            _ => null,
        };

        return Task.FromResult(new FirewallCapabilityReport
        {
            // A connected filter whose latest report rejects the rules file is degraded, not
            // available: the table in force is not the one the daemon published (review #2 MAC-1).
            Status = enforcement.Connected && enforcement.Rules is not { IsError: true }
                ? FirewallCapabilityStatus.Available
                : FirewallCapabilityStatus.Degraded,
            Reason = reason,
            FirewallServiceRunning = enforcement.Connected,
            ManagedRulesReadable = true,
            ManagedRuleCount = state.Rules.Count,
            ProbedUtc = now,
            FilterEnforcement = ToEnforcementReport(enforcement),
        });
    }

    /// <summary>Maps the enforcement snapshot (and the last <c>filter.rules</c> event in it) to the IPC contract.</summary>
    public static FilterEnforcementReport ToEnforcementReport(FilterEnforcementSnapshot enforcement)
    {
        ArgumentNullException.ThrowIfNull(enforcement);
        var rules = enforcement.Rules;
        return new FilterEnforcementReport
        {
            State = enforcement.State,
            Connected = enforcement.Connected,
            PublishedGeneration = enforcement.PublishedGeneration,
            AckedGeneration = enforcement.AckedGeneration,
            LastSeenUtc = enforcement.LastSeenUtc,
            LastAckUtc = enforcement.LastAckUtc,
            Generation = rules?.Generation ?? -1,
            AppliedRuleCount = rules?.Applied ?? 0,
            RejectedRules = (rules?.Rejected ?? [])
                .Select(rejected => new FilterRuleRejection { RuleId = rejected.Id, Reason = rejected.Reason })
                .ToArray(),
            FileError = rules?.Error,
            DroppedEvents = rules?.Dropped ?? 0,
            ReportedUtc = rules?.ReceivedUtc ?? default,
        };
    }

    /// <summary>
    /// Owned rules with their state as of now: <see cref="RuleState.Applied"/> only while the
    /// published generation is verified and the filter did not reject the rule,
    /// <see cref="RuleState.Failed"/> for a rule the filter rejected, otherwise
    /// <see cref="RuleState.Pending"/>. The stored record keeps the outcome of the last write.
    /// A rule projected <see cref="RuleState.Applied"/> carries the time of the acknowledgement
    /// that verified it as <see cref="ManagedRule.LastVerifiedUtc"/>, also when that ack arrived
    /// after the apply call's bounded wait (it answered Pending and stored no time).
    /// </summary>
    public Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var state = LoadState();
        var enforcement = _status.Snapshot(state.Generation);
        return Task.FromResult<IReadOnlyList<ManagedRule>>(
            state.Rules.Select(rule => Project(rule, enforcement)).ToList());
    }

    private static ManagedRule Project(ManagedRule rule, FilterEnforcementSnapshot enforcement)
    {
        var projected = ProjectState(rule, enforcement);
        return rule with
        {
            State = projected,
            LastVerifiedUtc = projected == RuleState.Applied
                ? enforcement.LastAckUtc ?? rule.LastVerifiedUtc
                : rule.LastVerifiedUtc,
        };
    }

    /// <summary>Pure state projection of one stored rule under the current enforcement snapshot.</summary>
    public static RuleState ProjectState(ManagedRule rule, FilterEnforcementSnapshot enforcement)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(enforcement);
        var id = FilterRuleTable.ToFilterRule(rule.Spec).Id;
        if (enforcement.IsVerified)
        {
            // Verified generation: the rule is Applied only when it is proven in the acknowledged
            // effective table (published under this generation, not rejected, echoed by the filter
            // when it echoes ids); otherwise the filter runs a table without it.
            return enforcement.RuleVerified(id, rule.Spec.Enabled) ? RuleState.Applied : RuleState.Failed;
        }

        return rule.State == RuleState.Failed ? RuleState.Failed : RuleState.Pending;
    }

    public async Task<RuleApplyResult> UpsertOwnedRuleAsync(RuleSpec spec, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(spec);
        EnsureWriteGate();

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var now = _time.GetUtcNow();
            var state = LoadState();
            var rule = new ManagedRule
            {
                ManagedRuleId = spec.ManagedRuleId,
                OsRuleName = OwnedRuleName.Create(spec.ManagedRuleId, spec.Direction),
                OwnershipGroup = OwnedRuleOwnership.GroupName,
                Spec = spec,
                State = RuleState.Pending,
                LastVerifiedUtc = null,
            };

            var rules = state.Rules.Where(existing => existing.ManagedRuleId != spec.ManagedRuleId).Append(rule).ToList();
            var published = Publish(rules, state.Generation);

            var expected = FilterRuleTable.ToFilterRule(spec);
            var written = FilterRulesFile.TryRead(_paths.RulesFile)?.Rules
                .FirstOrDefault(candidate => string.Equals(candidate.Id, expected.Id, StringComparison.OrdinalIgnoreCase));

            if (!expected.SameAs(written))
            {
                return new RuleApplyResult
                {
                    Success = false,
                    ManagedRuleId = spec.ManagedRuleId,
                    State = RuleState.Failed,
                    OsRuleName = rule.OsRuleName,
                    ErrorCode = "rule.readback_mismatch",
                    ErrorMessage = $"rules.json generation {published} does not contain the expected rule.",
                };
            }

            // Published, not enforced: wait (bounded) for the extension's acknowledgement of this
            // generation and report exactly what it proved.
            await _status.WaitForAcknowledgementAsync(published, now, _ackTimeout, ct).ConfigureAwait(false);
            var result = Outcome(spec.ManagedRuleId, rule.OsRuleName, expected.Id, published, now, _status.Snapshot(published), spec.Enabled);
            SaveState(new ManagedRuleState
            {
                Generation = published,
                Rules = rules.Select(candidate => candidate.ManagedRuleId == spec.ManagedRuleId
                    ? candidate with { State = result.State, LastVerifiedUtc = result.VerifiedUtc, LastErrorCode = result.ErrorCode }
                    : candidate).ToList(),
            });
            return result;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return Failed(spec.ManagedRuleId, "filter.write_failed", exception.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Pure lifecycle decision after a publish (review 2026-11-12 P0 #2): the filter's
    /// acknowledgement of <paramref name="published"/> without a file error and without rejecting
    /// the rule is <see cref="RuleState.Applied"/> (verified at the ack time); a rejected file or
    /// rule is <see cref="RuleState.Failed"/> with the filter's reason; anything else is
    /// <see cref="RuleState.Pending"/> with a message naming why.
    /// </summary>
    public static RuleApplyResult Outcome(
        Guid managedRuleId,
        string? osRuleName,
        string filterRuleId,
        long published,
        DateTimeOffset publishedUtc,
        FilterEnforcementSnapshot enforcement,
        bool enabled = true)
    {
        ArgumentNullException.ThrowIfNull(enforcement);

        if (enforcement.FileRejectionSince(publishedUtc) is { } fileError)
        {
            return new RuleApplyResult
            {
                Success = false,
                ManagedRuleId = managedRuleId,
                State = RuleState.Failed,
                OsRuleName = osRuleName,
                ErrorCode = "filter.file_rejected",
                ErrorMessage = string.Create(
                    CultureInfo.InvariantCulture,
                    $"AxiomFilter rejected rules generation {published} ({fileError}); generation {enforcement.Rules?.Generation ?? -1} stays in force."),
            };
        }

        if (enforcement.IsVerified)
        {
            if (enforcement.RejectionReason(filterRuleId) is { } rejection)
            {
                return new RuleApplyResult
                {
                    Success = false,
                    ManagedRuleId = managedRuleId,
                    State = RuleState.Failed,
                    OsRuleName = osRuleName,
                    ErrorCode = "filter.rule_rejected",
                    ErrorMessage = $"AxiomFilter does not enforce this rule: {rejection}",
                };
            }

            if (!enforcement.RuleVerified(filterRuleId, enabled))
            {
                return new RuleApplyResult
                {
                    Success = false,
                    ManagedRuleId = managedRuleId,
                    State = RuleState.Failed,
                    OsRuleName = osRuleName,
                    ErrorCode = "filter.rule_not_effective",
                    ErrorMessage = string.Create(
                        CultureInfo.InvariantCulture,
                        $"AxiomFilter acknowledged rules generation {published} but its effective table does not contain this rule."),
                };
            }

            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = managedRuleId,
                State = RuleState.Applied,
                OsRuleName = osRuleName,
                VerifiedUtc = enforcement.LastAckUtc,
            };
        }

        var why = enforcement.State switch
        {
            FilterEnforcementState.Unavailable => " (the network extension has not connected)",
            FilterEnforcementState.Degraded => " (the network extension is disconnected)",
            _ => enforcement.AckedGeneration is { } acked
                ? string.Create(CultureInfo.InvariantCulture, $" (last acknowledged generation {acked})")
                : string.Empty,
        };
        return new RuleApplyResult
        {
            Success = true,
            ManagedRuleId = managedRuleId,
            State = RuleState.Pending,
            OsRuleName = osRuleName,
            ErrorCode = null,
            ErrorMessage = string.Create(CultureInfo.InvariantCulture, $"awaiting AxiomFilter acknowledgement of generation {published}{why}"),
        };
    }

    public async Task<RuleApplyResult> RemoveOwnedRuleAsync(Guid managedRuleId, CancellationToken ct)
    {
        if (managedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(managedRuleId));
        }

        EnsureWriteGate();

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var now = _time.GetUtcNow();
            var state = LoadState();
            var existing = state.Rules.FirstOrDefault(rule => rule.ManagedRuleId == managedRuleId);
            var rules = state.Rules.Where(rule => rule.ManagedRuleId != managedRuleId).ToList();
            var published = Publish(rules, state.Generation);

            // The rule is gone from the table; whether the filter stopped enforcing it is only
            // known once it acknowledged the new generation.
            await _status.WaitForAcknowledgementAsync(published, now, _ackTimeout, ct).ConfigureAwait(false);
            var enforcement = _status.Snapshot(published);
            var filterRuleId = FilterRuleId(managedRuleId);
            var verifiedAbsent = enforcement.RuleVerifiedAbsent(filterRuleId);
            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = managedRuleId,
                State = RuleState.Desired,
                OsRuleName = existing?.OsRuleName,
                VerifiedUtc = verifiedAbsent ? enforcement.LastAckUtc : null,
                ErrorMessage = verifiedAbsent
                    ? null
                    : string.Create(CultureInfo.InvariantCulture, $"removed from rules.json; awaiting AxiomFilter acknowledgement of generation {published}"),
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return Failed(managedRuleId, "filter.write_failed", exception.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Recovery read: the captured identity must still be in <c>managed-rules.json</c> with the
    /// strict <c>Axiom::{id}::{OUT|IN}</c> name, the same direction and Axiom ownership metadata.
    /// <see cref="OwnedRulePresence.Absent"/> means "proven absent": gone from the record <b>and</b>
    /// the filter acknowledged the current table without it (review #2 MAC-2). A rule that is gone
    /// from the record but whose removal the filter has not acknowledged yet (removal attempted
    /// while the extension was offline, daemon crash between publish and ack) is still reported as
    /// <see cref="OwnedRulePresence.Owned"/> so the recovery controller retries
    /// <see cref="RemoveCapturedOwnedRuleAsync"/>, which is idempotent and answers with the ack state.
    /// </summary>
    public Task<OwnedRulePresence> InspectOwnedRuleAsync(
        Guid managedRuleId,
        FirewallDirection direction,
        CancellationToken ct)
    {
        if (managedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(managedRuleId));
        }

        ct.ThrowIfCancellationRequested();
        var state = LoadState();
        var existing = state.Rules.FirstOrDefault(rule => rule.ManagedRuleId == managedRuleId);
        if (existing is null)
        {
            return Task.FromResult(
                _status.Snapshot(state.Generation).RuleVerifiedAbsent(FilterRuleId(managedRuleId))
                    ? OwnedRulePresence.Absent
                    : OwnedRulePresence.Owned);
        }

        return Task.FromResult(
            existing.Spec.Direction == direction && OwnedRuleOwnership.IsRecoverable(existing)
                ? OwnedRulePresence.Owned
                : OwnedRulePresence.ForeignOrChanged);
    }

    /// <summary>
    /// Recovery-only removal of one captured rule in one direction. Like Windows it is not behind
    /// the interactive write gate (it must work while the shield is off) but is refused outside the
    /// root daemon or an explicitly privileged administrator process, and it re-checks ownership
    /// immediately before republishing the table without the rule.
    /// </summary>
    public async Task<RuleApplyResult> RemoveCapturedOwnedRuleAsync(
        Guid managedRuleId,
        FirewallDirection direction,
        CancellationToken ct)
    {
        if (managedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(managedRuleId));
        }

        if (!ProtectionWriteConsent.IsServiceHost && !Environment.IsPrivilegedProcess)
        {
            throw new UnauthorizedAccessException(
                "Network recovery removal requires the root axiomd daemon or an administrator recovery command.");
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var now = _time.GetUtcNow();
            var state = LoadState();
            var filterRuleId = FilterRuleId(managedRuleId);
            var existing = state.Rules.FirstOrDefault(rule => rule.ManagedRuleId == managedRuleId);
            if (existing is null)
            {
                // Already gone from the record (earlier attempt, crash between publish and ack):
                // idempotent retry. Verified absent only with a current acknowledgement of the
                // table that lacks the rule; otherwise wait for one, bounded, and say what is missing.
                await _status.WaitForAcknowledgementAsync(state.Generation, DateTimeOffset.MinValue, _ackTimeout, ct).ConfigureAwait(false);
                return RecoveryOutcome(managedRuleId, null, filterRuleId, state.Generation, DateTimeOffset.MinValue, _status.Snapshot(state.Generation));
            }

            if (existing.Spec.Direction != direction || !OwnedRuleOwnership.IsRecoverable(existing))
            {
                return Failed(managedRuleId, "rule.not_owned", "The rule identity exists but its ownership metadata changed; it was not removed.");
            }

            // Same discipline as RemoveOwnedRuleAsync (review #2 MAC-2): publish the table without
            // the rule, wait (bounded) for the extension's acknowledgement of that generation, and
            // report exactly what it proved. Unrelated rules are republished unchanged.
            var published = Publish(state.Rules.Where(rule => rule.ManagedRuleId != managedRuleId).ToList(), state.Generation);
            await _status.WaitForAcknowledgementAsync(published, now, _ackTimeout, ct).ConfigureAwait(false);
            return RecoveryOutcome(managedRuleId, existing.OsRuleName, filterRuleId, published, now, _status.Snapshot(published));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return Failed(managedRuleId, "filter.write_failed", exception.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Pure lifecycle decision for a recovery removal (review #2 MAC-2). Four outcomes are kept
    /// apart: <b>verified</b> (the filter acknowledged <paramref name="published"/> on the current
    /// connection and its effective table has no such rule) → <c>Success</c>,
    /// <see cref="RuleState.Desired"/>, <c>VerifiedUtc</c> = ack time; <b>pending</b> (extension
    /// offline, or connected but no clean ack of this generation yet) → <c>Success = false</c>,
    /// <see cref="RuleState.Pending"/> with <c>filter.disconnected</c> / <c>filter.ack_pending</c>
    /// and an actionable message; <b>failed</b> (file rejected, or the filter still enforces the
    /// rule) → <see cref="RuleState.Failed"/>. A verification timestamp is never derived from the
    /// clock or the file write, so the recovery controller counts the rule as removed only when
    /// the filter proved it (otherwise the problem is listed and the result is not "verified").
    /// </summary>
    public static RuleApplyResult RecoveryOutcome(
        Guid managedRuleId,
        string? osRuleName,
        string filterRuleId,
        long published,
        DateTimeOffset publishedUtc,
        FilterEnforcementSnapshot enforcement)
    {
        ArgumentNullException.ThrowIfNull(enforcement);
        var generation = published.ToString(CultureInfo.InvariantCulture);

        if (enforcement.FileRejectionSince(publishedUtc) is { } fileError)
        {
            return new RuleApplyResult
            {
                Success = false,
                ManagedRuleId = managedRuleId,
                State = RuleState.Failed,
                OsRuleName = osRuleName,
                ErrorCode = "filter.file_rejected",
                ErrorMessage = string.Create(
                    CultureInfo.InvariantCulture,
                    $"AxiomFilter rejected rules generation {generation} ({fileError}); generation {enforcement.Rules?.Generation ?? -1} stays in force, so the Axiom rule may still be enforced. The removal is not verified; fix the rules file and run the recovery again."),
            };
        }

        if (enforcement.RuleVerifiedAbsent(filterRuleId))
        {
            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = managedRuleId,
                State = RuleState.Desired,
                OsRuleName = osRuleName,
                VerifiedUtc = enforcement.LastAckUtc,
            };
        }

        if (enforcement.IsVerified)
        {
            return new RuleApplyResult
            {
                Success = false,
                ManagedRuleId = managedRuleId,
                State = RuleState.Failed,
                OsRuleName = osRuleName,
                ErrorCode = "filter.rule_still_enforced",
                ErrorMessage = string.Create(
                    CultureInfo.InvariantCulture,
                    $"AxiomFilter acknowledged rules generation {generation} but its effective table still contains the Axiom rule. The removal is not verified; run the recovery again."),
            };
        }

        var (code, why) = enforcement.State switch
        {
            FilterEnforcementState.Unavailable => (
                "filter.disconnected",
                "AxiomFilter has not reported to this process (the network extension is off, or the Axiom service is stopped and this is the offline recovery), so the rule may still be enforced. " +
                "Enable the extension (`axiom-sysext enable`), start the Axiom service (it republishes the table and waits for the extension on connect) and run Restore network settings again"),
            FilterEnforcementState.Degraded => (
                "filter.disconnected",
                "the AxiomFilter network extension is not connected" +
                (enforcement.LastSeenUtc is { } seen ? " (last seen " + Utc(seen) + ")" : string.Empty) +
                ", so the rule may still be enforced. Enable the extension (System Settings → Network → Filters, or `axiom-sysext enable`) and run the recovery again"),
            _ => (
                "filter.ack_pending",
                "AxiomFilter has not acknowledged rules generation " + generation +
                (enforcement.AckedGeneration is { } acked ? " (last acknowledged " + acked.ToString(CultureInfo.InvariantCulture) + ")" : string.Empty) +
                ", so the rule may still be enforced. Run the recovery again once the extension reports the current generation"),
        };
        return new RuleApplyResult
        {
            Success = false,
            ManagedRuleId = managedRuleId,
            State = RuleState.Pending,
            OsRuleName = osRuleName,
            ErrorCode = code,
            ErrorMessage = $"The Axiom rule was removed from rules.json but the removal is not verified: {why}.",
        };
    }

    private static string FilterRuleId(Guid managedRuleId) => managedRuleId.ToString("D", CultureInfo.InvariantCulture);

    public Task<EffectiveRuleReport> VerifyAsync(RuleSpec spec, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.ManagedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(spec));
        }

        ct.ThrowIfCancellationRequested();
        return Task.FromResult(Verify(spec, FilterRulesFile.TryRead(_paths.RulesFile), _status, _time.GetUtcNow()));
    }

    /// <summary>
    /// Compares a spec with the published table and the filter's acknowledgement (pure, for
    /// tests). <see cref="EffectiveRuleReport.EffectiveAction"/> is set only when the published
    /// generation is verified (connected + acknowledged on this connection, no file error) and the
    /// filter did not reject the rule; otherwise it is null and a note says why (review P0 #3).
    /// </summary>
    public static EffectiveRuleReport Verify(
        RuleSpec spec,
        FilterRuleTable? table,
        FilterStatus status,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(status);

        var notes = new List<string>();
        if (table is null)
        {
            notes.Add("rules.json is missing or invalid; the filter keeps its last good table (fail-open at first start).");
            return new EffectiveRuleReport
            {
                ManagedRuleId = spec.ManagedRuleId,
                PresentInOs = false,
                MatchesSpec = false,
                EffectiveAction = null,
                ObservedUtc = now,
                Notes = notes,
                EnforcementVerified = false,
            };
        }

        var expected = FilterRuleTable.ToFilterRule(spec);
        var written = table.Rules.FirstOrDefault(rule =>
            string.Equals(rule.Id, expected.Id, StringComparison.OrdinalIgnoreCase));
        var enforcement = status.Snapshot(table.Generation);

        notes.Add(string.Create(CultureInfo.InvariantCulture, $"rules.json generation {table.Generation}."));
        switch (enforcement.State)
        {
            case FilterEnforcementState.Unavailable:
                notes.Add("AxiomFilter has never connected; the rule is published but not enforced.");
                break;
            case FilterEnforcementState.Degraded:
                notes.Add("AxiomFilter is disconnected (last seen " + Utc(enforcement.LastSeenUtc) + "); the rule is published but not known to be enforced.");
                break;
            case FilterEnforcementState.Pending when enforcement.Rules is { IsError: true }:
                // The latest report is a file rejection; the file-error note below says why. An
                // earlier ack of the same number is history, not "acknowledged" (review #2 MAC-1).
                notes.Add("AxiomFilter's latest report rejects the rules file; enforcement of this table is not verified.");
                break;
            case FilterEnforcementState.Pending:
                notes.Add(enforcement.AckedGeneration is { } acked
                    ? string.Create(CultureInfo.InvariantCulture, $"AxiomFilter acknowledged generation {acked}, not {table.Generation}; enforcement of this table is pending.")
                    : string.Create(CultureInfo.InvariantCulture, $"AxiomFilter has not acknowledged generation {table.Generation} yet; enforcement is pending."));
                break;
            default:
                notes.Add("AxiomFilter acknowledged generation " + table.Generation.ToString(CultureInfo.InvariantCulture) + " at " + Utc(enforcement.LastAckUtc) + ".");
                break;
        }

        if (written is null)
        {
            notes.Add("The rule is not in rules.json.");
        }
        else if (!expected.SameAs(written))
        {
            notes.Add("The rule in rules.json differs from the stored spec.");
        }

        // The filter's own verdict on this rule (review #6): a rejected rule is published but not
        // enforced, so it has no effective action even though it is present in the table.
        string? rejection = null;
        if (enforcement.Rules is { } report)
        {
            if (report.Error is { Length: > 0 } fileError)
            {
                notes.Add(string.Create(
                    CultureInfo.InvariantCulture,
                    $"AxiomFilter rejected the rules file ({fileError}); generation {report.Generation} stays in force."));
            }

            rejection = enforcement.RejectionReason(expected.Id);
            if (rejection is not null)
            {
                notes.Add($"AxiomFilter rejected this rule and does not enforce it: {rejection}");
            }
        }

        // Per-rule proof (review #2 MAC-1): the generation being verified is necessary, not
        // sufficient. The rule must be in the table as published (present, same content), the
        // daemon must have published it under this generation, and the filter must not have
        // rejected it (and must list it when it echoes its effective ids).
        var matches = expected.SameAs(written);
        var ruleVerified = enforcement.RuleVerified(expected.Id, expected.Enabled);
        if (enforcement.IsVerified && rejection is null && !ruleVerified)
        {
            notes.Add(enforcement.ExpectedRuleIds is null
                ? "The published table for this generation is not known to this daemon process; the rule is not verified."
                : "The acknowledged effective table does not contain this rule; it is not verified.");
        }

        var verified = enforcement.IsVerified && rejection is null && written is not null && matches && ruleVerified;
        return new EffectiveRuleReport
        {
            ManagedRuleId = spec.ManagedRuleId,
            PresentInOs = written is not null,
            MatchesSpec = matches,
            EffectiveAction = verified && written is { Enabled: true }
                ? string.Equals(written.Action, FilterRuleTable.ActionBlock, StringComparison.Ordinal)
                    ? FirewallAction.Block
                    : FirewallAction.Allow
                : null,
            ObservedUtc = now,
            Notes = notes,
            FilterRejectionReason = rejection,
            EnforcementVerified = verified,
        };
    }

    /// <summary>Republishes rules.json from the owned rules (daemon start) and returns the generation.</summary>
    public async Task<long> PublishAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var state = LoadState();
            return Publish(state.Rules, state.Generation);
        }
        finally
        {
            _gate.Release();
        }
    }

    private long Publish(IReadOnlyList<ManagedRule> rules, long stateGeneration)
    {
        var fileGeneration = FilterRulesFile.TryRead(_paths.RulesFile)?.Generation ?? 0;
        var generation = Math.Max(stateGeneration, fileGeneration) + 1;

        // Persist ownership first: a crash between the two writes leaves the next start able to
        // republish the complete table, never a table with rules the daemon no longer knows.
        SaveState(new ManagedRuleState { Generation = generation, Rules = rules });
        var table = FilterRuleTable.Create(rules.Select(rule => rule.Spec), generation);
        FilterRulesFile.WriteAtomic(_paths.RulesFile, table);
        // Expected-rules snapshot for this generation: the acknowledgement is matched against it.
        _status.Published(generation, table.Rules.Select(rule => rule.Id));
        return generation;
    }

    private ManagedRuleState LoadState()
    {
        try
        {
            if (!File.Exists(_paths.ManagedRulesFile))
            {
                return new ManagedRuleState();
            }

            var state = JsonSerializer.Deserialize<ManagedRuleState>(File.ReadAllText(_paths.ManagedRulesFile), StateJson);
            // managed-rules.json is the daemon's own 0600 record, so every entry is Axiom-owned;
            // records written before the recovery feature carry no group and get the marker here.
            return state is { SchemaVersion: ManagedRuleState.CurrentSchemaVersion }
                ? state with
                {
                    Rules = (state.Rules ?? [])
                        .Where(rule => rule.ManagedRuleId != Guid.Empty)
                        .Select(rule => string.IsNullOrWhiteSpace(rule.OwnershipGroup)
                            ? rule with { OwnershipGroup = OwnedRuleOwnership.GroupName }
                            : rule)
                        .ToList(),
                }
                : new ManagedRuleState();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new ManagedRuleState();
        }
    }

    private void SaveState(ManagedRuleState state) =>
        FilterRulesFile.WriteAtomic(_paths.ManagedRulesFile, JsonSerializer.Serialize(state, StateJson) + "\n", FilterRulesFile.PrivateMode);

    private bool TryProbeWritable(out string problem)
    {
        try
        {
            Directory.CreateDirectory(_paths.FilterDirectory);
            var probe = Path.Combine(_paths.FilterDirectory, $".probe-{Guid.NewGuid():N}");
            File.WriteAllText(probe, string.Empty);
            File.Delete(probe);
            problem = string.Empty;
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            problem = exception.Message;
            return false;
        }
    }

    private void EnsureWriteGate()
    {
        if (!_writeGate())
        {
            throw new NotSupportedException(
                ProtectionWriteConsent.Granted
                    ? "Firewall writes require the root axiomd launchd daemon."
                    : "Firewall writes are disabled. Enable Axiom Shield in the app, or set " +
                      $"{FirewallWriteGate.WriteEnableVariable}=1 and {FirewallWriteGate.WriteConfirmVariable}=yes on an isolated test VM.");
        }
    }

    private static string Utc(DateTimeOffset? value) => value?.ToString("u", CultureInfo.InvariantCulture) ?? "never";

    private static RuleApplyResult Failed(Guid id, string code, string message) => new()
    {
        Success = false,
        ManagedRuleId = id,
        State = RuleState.Failed,
        ErrorCode = code,
        ErrorMessage = message,
    };

    private sealed record ManagedRuleState
    {
        public const int CurrentSchemaVersion = 1;

        public int SchemaVersion { get; init; } = CurrentSchemaVersion;

        public long Generation { get; init; }

        public IReadOnlyList<ManagedRule> Rules { get; init; } = [];
    }
}
