// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Core.Enforcement;

/// <summary>
/// Platform process-start feed. The service subscribes once and forwards every event to
/// <see cref="ProcessSpawnAuditHandler"/>; implementations own their OS subscription.
/// </summary>
public interface IProcessStartSource : IDisposable
{
    event EventHandler<ProcessSpawnEvent>? ProcessStarted;

    void Start();
}
