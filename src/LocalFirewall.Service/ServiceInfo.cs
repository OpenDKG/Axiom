// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Principal;
using LocalFirewall.Contracts;

namespace LocalFirewall.Service;

public static class ServiceInfo
{
    public const string ServiceName = "LocalFirewall";

    public const string DisplayName = "LocalFirewall";

    /// <summary>Set explicitly at process start so uptime is not affected by lazy type loading.</summary>
    public static DateTimeOffset StartedUtc { get; private set; } = DateTimeOffset.UtcNow;

    public static void MarkStarted() => StartedUtc = DateTimeOffset.UtcNow;

    /// <summary>
    /// SID allowed to call the pipe. The installer (FND-009) writes the interactive user's SID to
    /// LOCALFIREWALL_ALLOWED_SID; in console development mode the current user is used.
    /// </summary>
    public static string ResolveAllowedSid()
    {
        var configured = Environment.GetEnvironmentVariable("LOCALFIREWALL_ALLOWED_SID");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured.Trim();
        }

        return WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("Cannot determine the allowed SID.");
    }

    public static string Milestone => ProductMilestone.Current;
}
