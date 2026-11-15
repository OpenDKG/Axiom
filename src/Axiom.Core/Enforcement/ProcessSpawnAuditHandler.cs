// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Core.Enforcement;

/// <summary>Destination for a process-spawn audit row (graph writer, UI feed, test double).</summary>
public interface IProcessSpawnAuditSink
{
    void Record(ProcessSpawnAudit audit);
}

/// <summary>
/// F-19 wiring seam: the service's process-start subscription calls
/// <see cref="OnProcessStarted"/>; the handler applies the monitor (policy + de-duplication) and
/// forwards only Record/Block rows to the sink. Pure and unit-testable; the OS subscription and
/// any termination stay in the service layer.
/// </summary>
public sealed class ProcessSpawnAuditHandler
{
    private readonly Lock _sync = new();
    private readonly AgentProcessSpawnMonitor _monitor;
    private readonly IProcessSpawnAuditSink _sink;
    private int _recorded;

    public ProcessSpawnAuditHandler(AgentProcessSpawnMonitor monitor, IProcessSpawnAuditSink sink)
    {
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
    }

    /// <summary>Number of rows forwarded to the sink since the handler was created.</summary>
    public int Recorded
    {
        get
        {
            lock (_sync)
            {
                return _recorded;
            }
        }
    }

    /// <summary>
    /// Handles one process-start observation. Returns true when a row was written to the sink.
    /// </summary>
    public bool OnProcessStarted(
        ProcessSpawnEvent spawn,
        IReadOnlyCollection<string>? allowlist = null)
    {
        // WMI process-start callbacks can arrive concurrently across threadpool threads.
        lock (_sync)
        {
            var audit = _monitor.Observe(spawn, allowlist);
            if (audit is null)
            {
                return false;
            }

            _sink.Record(audit);
            _recorded++;
            return true;
        }
    }
}
