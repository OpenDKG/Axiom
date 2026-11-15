// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Core.Enforcement;

/// <summary>One recorded process-creation observation and the policy verdict for it.</summary>
public sealed record ProcessSpawnAudit(ProcessSpawnEvent Spawn, ProcessSpawnDecision Decision);

/// <summary>
/// F-19 part B: de-duplicates process-creation observations before the service records them.
/// The ETW/WMI subscription calls <see cref="Observe"/>; Allow verdicts are dropped, and an
/// identical (image, pid, parent) observation is only returned once so a noisy poll loop cannot
/// flood the graph. Pure and unit-testable; the subscription and any termination remain in the
/// service layer.
/// </summary>
public sealed class AgentProcessSpawnMonitor
{
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<string> _order = new();
    private readonly int _capacity;

    public AgentProcessSpawnMonitor(int capacity = 256)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _capacity = capacity;
    }

    /// <summary>Number of distinct non-allowed observations currently remembered.</summary>
    public int Count => _seen.Count;

    /// <summary>
    /// Evaluates one spawn. Returns null for an allowed child or for an observation already seen;
    /// otherwise returns the audit row to record.
    /// </summary>
    public ProcessSpawnAudit? Observe(
        ProcessSpawnEvent spawn,
        IReadOnlyCollection<string>? allowlist = null)
    {
        ArgumentNullException.ThrowIfNull(spawn);

        var decision = AgentProcessSpawnPolicy.Evaluate(spawn, allowlist);
        if (decision.Verdict == ProcessSpawnVerdict.Allow)
        {
            return null;
        }

        var key = string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{spawn.ImagePath}|{spawn.ProcessId}|{spawn.ParentProcessId}");
        if (!_seen.Add(key))
        {
            return null;
        }

        _order.Enqueue(key);
        while (_order.Count > _capacity)
        {
            _seen.Remove(_order.Dequeue());
        }

        return new ProcessSpawnAudit(spawn, decision);
    }
}
