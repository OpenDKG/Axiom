// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Enforcement;

namespace Axiom.Service;

/// <summary>
/// Binds a process-start source to the audit handler. Separated from the hosted worker so the
/// subscription lifecycle is unit-testable with a fake source.
/// </summary>
public sealed class ProcessSpawnAuditRuntime : IDisposable
{
    private readonly IProcessStartSource _source;
    private readonly ProcessSpawnAuditHandler _handler;
    private bool _started;

    public ProcessSpawnAuditRuntime(IProcessStartSource source, ProcessSpawnAuditHandler handler)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
    }

    public int Recorded => _handler.Recorded;

    public void Start()
    {
        if (_started)
        {
            return;
        }

        _source.ProcessStarted += OnProcessStarted;
        _source.Start();
        _started = true;
    }

    public void Dispose()
    {
        if (!_started)
        {
            _source.Dispose();
            return;
        }

        _started = false;
        _source.ProcessStarted -= OnProcessStarted;
        _source.Dispose();
    }

    private void OnProcessStarted(object? sender, ProcessSpawnEvent spawn) =>
        _handler.OnProcessStarted(spawn);
}
