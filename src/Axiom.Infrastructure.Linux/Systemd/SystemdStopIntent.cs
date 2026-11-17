// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Systemd;

/// <summary>Stub (red tests).</summary>
public sealed class SystemdStopIntent(IProcessRunner runner, string markerPath, Action<string> log)
{
    public const string MarkerFileName = "bpf-handover";

    public bool KeepEnforcementAcrossStop()
    {
        _ = runner;
        _ = markerPath;
        _ = log;
        return false;
    }

    public static bool? Classify(string listJobs, string unit)
    {
        _ = listJobs;
        _ = unit;
        return false;
    }
}
