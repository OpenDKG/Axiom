// SPDX-License-Identifier: GPL-3.0-or-later
namespace Netpetra.Contracts.Blackbox;

/// <summary>
/// Pure state classifier for Netpetra-owned agent adapters. File presence alone never becomes
/// protected; runtime evidence and Blackbox availability are explicit inputs.
/// </summary>
public static class AgentProtectionClassifier
{
    public static string Classify(
        bool detected,
        bool hookConfigured,
        bool runtimeObserved,
        bool failureObserved,
        bool blackboxAvailable,
        bool verifiedBlocking = false,
        bool auditOnly = false,
        bool trustRequired = false)
    {
        if (!detected)
        {
            return "NOT DETECTED";
        }

        if (!hookConfigured)
        {
            return "DETECTED";
        }

        if (!blackboxAvailable)
        {
            return "OFFLINE";
        }

        if (trustRequired)
        {
            return "TRUST REQUIRED";
        }

        if (failureObserved)
        {
            return "DEGRADED";
        }

        if (verifiedBlocking)
        {
            return "VERIFIED BLOCKING";
        }

        if (runtimeObserved)
        {
            return auditOnly ? "AUDIT ONLY" : "HOOK LOADED";
        }

        return "HOOK INSTALLED";
    }
}
