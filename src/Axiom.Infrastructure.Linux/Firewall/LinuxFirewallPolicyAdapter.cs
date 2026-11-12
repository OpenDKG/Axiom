// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Axiom.Core.Protection;
using Axiom.Infrastructure.Unix.Filter;

namespace Axiom.Infrastructure.Linux.Firewall;

/// <summary>
/// Linux firewall adapter, enforcement stub. The nftables engine (<c>Nft/</c>, built on its own
/// branch) replaces this class; until then the daemon behaves like Windows with the firewall
/// service stopped: capabilities report <see cref="FirewallCapabilityStatus.Unavailable"/> with
/// <see cref="EnforcementUnavailableReason"/>, desired rules are still recorded in
/// <c>filter/managed-rules.json</c> (shared <see cref="ManagedRuleStore"/>, state
/// <see cref="RuleState.Desired"/>) so they survive to the first engine, and network recovery
/// (<see cref="IOwnedRuleRecoveryAdapter"/>) works over the same record. Writes require the
/// same gate as Windows and macOS (<see cref="FirewallWriteGate"/>).
/// </summary>
public sealed class LinuxFirewallPolicyAdapter : IFirewallPolicyAdapter, IOwnedRuleRecoveryAdapter, IDisposable
{
    public const string EnforcementUnavailableReason =
        "Firewall enforcement is not available on Linux in this build: the nftables engine is not wired yet. " +
        "Rules are stored and will be enforced once it is.";

    private readonly LinuxServicePaths _paths;

    private readonly ManagedRuleStore _store;

    private readonly Func<bool> _writeGate;

    private readonly TimeProvider _time;

    private readonly SemaphoreSlim _gate = new(1, 1);

    public LinuxFirewallPolicyAdapter(LinuxServicePaths paths)
        : this(paths, () => FirewallWriteGate.IsOpen, TimeProvider.System)
    {
    }

    public LinuxFirewallPolicyAdapter(LinuxServicePaths paths, Func<bool> writeGate, TimeProvider time)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _writeGate = writeGate ?? throw new ArgumentNullException(nameof(writeGate));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _store = new ManagedRuleStore(_paths.ManagedRulesFile);
    }

    public void Dispose() => _gate.Dispose();

    public Task<FirewallCapabilityReport> GetCapabilitiesAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var now = _time.GetUtcNow();
        var readable = TryProbeWritable(out var problem);
        var state = _store.Load();
        return Task.FromResult(new FirewallCapabilityReport
        {
            Status = FirewallCapabilityStatus.Unavailable,
            Reason = readable
                ? EnforcementUnavailableReason
                : $"{EnforcementUnavailableReason} The rule record {_paths.ManagedRulesFile} is not writable ({problem}).",
            FirewallServiceRunning = false,
            ManagedRulesReadable = readable,
            ManagedRuleCount = readable ? state.Rules.Count : null,
            ProbedUtc = now,
        });
    }

    public Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult<IReadOnlyList<ManagedRule>>(_store.Load().Rules);
    }

    public async Task<RuleApplyResult> UpsertOwnedRuleAsync(RuleSpec spec, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(spec);
        EnsureWriteGate();

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var now = _time.GetUtcNow();
            var state = _store.Load();
            var rule = new ManagedRule
            {
                ManagedRuleId = spec.ManagedRuleId,
                OsRuleName = OwnedRuleName.Create(spec.ManagedRuleId, spec.Direction),
                OwnershipGroup = OwnedRuleOwnership.GroupName,
                Spec = spec,
                State = RuleState.Desired,
                LastVerifiedUtc = now,
            };
            var rules = state.Rules.Where(existing => existing.ManagedRuleId != spec.ManagedRuleId).Append(rule).ToList();
            _store.Save(state with { Generation = state.Generation + 1, Rules = rules });

            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = spec.ManagedRuleId,
                State = RuleState.Desired,
                OsRuleName = rule.OsRuleName,
                ErrorCode = "enforcement.unavailable",
                ErrorMessage = EnforcementUnavailableReason,
                VerifiedUtc = now,
            };
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
            return Remove(managedRuleId, null);
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

    public Task<OwnedRulePresence> InspectOwnedRuleAsync(Guid managedRuleId, FirewallDirection direction, CancellationToken ct)
    {
        if (managedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(managedRuleId));
        }

        ct.ThrowIfCancellationRequested();
        var existing = _store.Load().Rules.FirstOrDefault(rule => rule.ManagedRuleId == managedRuleId);
        if (existing is null)
        {
            return Task.FromResult(OwnedRulePresence.Absent);
        }

        return Task.FromResult(
            existing.Spec.Direction == direction && OwnedRuleOwnership.IsRecoverable(existing)
                ? OwnedRulePresence.Owned
                : OwnedRulePresence.ForeignOrChanged);
    }

    /// <summary>Recovery-only removal; same authorization rule as the macOS and Windows adapters.</summary>
    public async Task<RuleApplyResult> RemoveCapturedOwnedRuleAsync(Guid managedRuleId, FirewallDirection direction, CancellationToken ct)
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
            return Remove(managedRuleId, direction);
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

    public Task<EffectiveRuleReport> VerifyAsync(RuleSpec spec, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.ManagedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(spec));
        }

        ct.ThrowIfCancellationRequested();
        var stored = _store.Load().Rules.FirstOrDefault(rule => rule.ManagedRuleId == spec.ManagedRuleId);
        return Task.FromResult(new EffectiveRuleReport
        {
            ManagedRuleId = spec.ManagedRuleId,
            PresentInOs = false,
            MatchesSpec = false,
            EffectiveAction = null,
            ObservedUtc = _time.GetUtcNow(),
            Notes =
            [
                stored is null ? "The rule is not in managed-rules.json." : "The rule is recorded in managed-rules.json (desired, not enforced).",
                EnforcementUnavailableReason,
            ],
        });
    }

    private RuleApplyResult Remove(Guid managedRuleId, FirewallDirection? direction)
    {
        var state = _store.Load();
        var existing = state.Rules.FirstOrDefault(rule => rule.ManagedRuleId == managedRuleId);
        if (existing is not null && direction is { } expected &&
            (existing.Spec.Direction != expected || !OwnedRuleOwnership.IsRecoverable(existing)))
        {
            return Failed(managedRuleId, "rule.not_owned", "The rule identity exists but its ownership metadata changed; it was not removed.");
        }

        if (existing is not null)
        {
            _store.Save(state with
            {
                Generation = state.Generation + 1,
                Rules = state.Rules.Where(rule => rule.ManagedRuleId != managedRuleId).ToList(),
            });
        }

        return new RuleApplyResult
        {
            Success = true,
            ManagedRuleId = managedRuleId,
            State = RuleState.Desired,
            OsRuleName = existing?.OsRuleName,
            VerifiedUtc = _time.GetUtcNow(),
        };
    }

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
                    ? "Firewall writes require the root axiomd systemd daemon."
                    : "Firewall writes are disabled. Enable Axiom Shield in the app, or set " +
                      $"{FirewallWriteGate.WriteEnableVariable}=1 and {FirewallWriteGate.WriteConfirmVariable}=yes on an isolated test VM.");
        }
    }

    private static RuleApplyResult Failed(Guid id, string code, string message) => new()
    {
        Success = false,
        ManagedRuleId = id,
        State = RuleState.Failed,
        ErrorCode = code,
        ErrorMessage = message,
    };
}
