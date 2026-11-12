// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Service;

public enum NetworkWatchdogAction
{
    None = 0,
    RestartResolver = 1,
    RestoreDns = 2,
}

/// <summary>
/// Decides what the service watchdog may do when adapters point at the loopback resolver. A running
/// resolver means the loopback DNS is intentional (including when the desktop is closed), so the
/// watchdog leaves it alone. A stopped resolver is either an interrupted start or a failed disable:
/// the first attempt restarts it when it is wanted, and only after that is DNS rolled back. DNS-only
/// rollback cannot disable an intentionally active firewall protection.
/// </summary>
public static class NetworkWatchdog
{
    public static NetworkWatchdogAction Decide(
        bool resolverEnabled,
        bool resolverRunning,
        bool loopbackDns,
        bool resolverRestartAttempted)
    {
        if (resolverRunning || !loopbackDns)
        {
            return NetworkWatchdogAction.None;
        }

        return resolverEnabled && !resolverRestartAttempted
            ? NetworkWatchdogAction.RestartResolver
            : NetworkWatchdogAction.RestoreDns;
    }
}
