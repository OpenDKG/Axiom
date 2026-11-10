// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;

namespace Axiom.Infrastructure.MacOS.Filter;

/// <summary>
/// macOS firewall adapter. The "OS firewall" is the AxiomFilter system extension, which enforces
/// the table the daemon publishes to <c>filter/rules.json</c>. The adapter owns
/// <c>filter/managed-rules.json</c> (its durable record of Axiom-owned rules, the equivalent of the
/// Axiom-named Windows Firewall rules) and republishes rules.json atomically with a new generation
/// after every change. Writes require the same gate as Windows (<see cref="FirewallWriteGate"/>).
/// </summary>
public sealed class MacFirewallPolicyAdapter : IFirewallPolicyAdapter, IDisposable
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

    public MacFirewallPolicyAdapter(MacServicePaths paths, FilterStatus status)
        : this(paths, status, () => FirewallWriteGate.IsOpen, TimeProvider.System)
    {
    }

    public MacFirewallPolicyAdapter(
        MacServicePaths paths,
        FilterStatus status,
        Func<bool> writeGate,
        TimeProvider time)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _status = status ?? throw new ArgumentNullException(nameof(status));
        _writeGate = writeGate ?? throw new ArgumentNullException(nameof(writeGate));
        _time = time ?? throw new ArgumentNullException(nameof(time));
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
                FirewallServiceRunning = _status.HasRecentHello(now),
                ManagedRulesReadable = false,
                ManagedRuleCount = null,
                ProbedUtc = now,
            });
        }

        var state = LoadState();
        var hello = _status.HasRecentHello(now);
        string? reason = null;
        if (!hello)
        {
            reason = "The AxiomFilter network extension has not connected to " +
                     $"{_paths.FilterSocketPath}; rules are written to {_paths.RulesFile} " +
                     "but are not enforced until the extension is activated.";
        }
        else if (_status.LoadedGeneration is { } loaded && loaded < state.Generation)
        {
            reason = $"AxiomFilter has loaded rules generation {loaded}; generation {state.Generation} is pending.";
        }

        return Task.FromResult(new FirewallCapabilityReport
        {
            Status = FirewallCapabilityStatus.Available,
            Reason = reason,
            FirewallServiceRunning = hello,
            ManagedRulesReadable = true,
            ManagedRuleCount = state.Rules.Count,
            ProbedUtc = now,
        });
    }

    public Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult<IReadOnlyList<ManagedRule>>(LoadState().Rules);
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
                Spec = spec,
                State = RuleState.Applied,
                LastVerifiedUtc = now,
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

            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = spec.ManagedRuleId,
                State = RuleState.Applied,
                OsRuleName = rule.OsRuleName,
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
            var state = LoadState();
            var existing = state.Rules.FirstOrDefault(rule => rule.ManagedRuleId == managedRuleId);
            var rules = state.Rules.Where(rule => rule.ManagedRuleId != managedRuleId).ToList();
            Publish(rules, state.Generation);

            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = managedRuleId,
                State = RuleState.Desired,
                OsRuleName = existing?.OsRuleName,
                VerifiedUtc = _time.GetUtcNow(),
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

    /// <summary>Compares a spec with the published table (pure, for tests).</summary>
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
            };
        }

        var expected = FilterRuleTable.ToFilterRule(spec);
        var written = table.Rules.FirstOrDefault(rule =>
            string.Equals(rule.Id, expected.Id, StringComparison.OrdinalIgnoreCase));

        notes.Add(string.Create(CultureInfo.InvariantCulture, $"rules.json generation {table.Generation}."));
        if (!status.HasRecentHello(now))
        {
            notes.Add("AxiomFilter is not connected; the rule is published but not enforced.");
        }
        else if (status.LoadedGeneration is { } loaded && loaded < table.Generation)
        {
            notes.Add(string.Create(CultureInfo.InvariantCulture, $"AxiomFilter reports generation {loaded}; reload pending."));
        }

        if (written is null)
        {
            notes.Add("The rule is not in rules.json.");
        }
        else if (!expected.SameAs(written))
        {
            notes.Add("The rule in rules.json differs from the stored spec.");
        }

        return new EffectiveRuleReport
        {
            ManagedRuleId = spec.ManagedRuleId,
            PresentInOs = written is not null,
            MatchesSpec = expected.SameAs(written),
            EffectiveAction = written is { Enabled: true }
                ? string.Equals(written.Action, FilterRuleTable.ActionBlock, StringComparison.Ordinal)
                    ? FirewallAction.Block
                    : FirewallAction.Allow
                : null,
            ObservedUtc = now,
            Notes = notes,
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
        FilterRulesFile.WriteAtomic(_paths.RulesFile, FilterRuleTable.Create(rules.Select(rule => rule.Spec), generation));
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
            return state is { SchemaVersion: ManagedRuleState.CurrentSchemaVersion }
                ? state with { Rules = (state.Rules ?? []).Where(rule => rule.ManagedRuleId != Guid.Empty).ToList() }
                : new ManagedRuleState();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new ManagedRuleState();
        }
    }

    private void SaveState(ManagedRuleState state) =>
        FilterRulesFile.WriteAtomic(_paths.ManagedRulesFile, JsonSerializer.Serialize(state, StateJson) + "\n");

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
