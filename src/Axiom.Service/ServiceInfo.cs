// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Principal;
using Axiom.Contracts;
using Axiom.Core.Protection;

namespace Axiom.Service;

public static class ServiceInfo
{
    public const string ServiceName = "Axiom";

    public const string DisplayName = "Axiom";

    /// <summary>Set explicitly at process start so uptime is not affected by lazy type loading.</summary>
    public static DateTimeOffset StartedUtc { get; private set; } = DateTimeOffset.UtcNow;

    public static void MarkStarted() => StartedUtc = DateTimeOffset.UtcNow;

    /// <summary>
    /// SID allowed to call the pipe. An installed service persists the interactive user's SID in the
    /// shield state; AXIOM_ALLOWED_SID overrides it, and console development falls back to the
    /// current user.
    /// </summary>
    public static string ResolveAllowedSid()
    {
        var configured = Environment.GetEnvironmentVariable("AXIOM_ALLOWED_SID")
                         ?? Environment.GetEnvironmentVariable(LegacyIdentity.ProductName + "_ALLOWED_SID");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured.Trim();
        }

        var persisted = new ProtectionSettingsStore().Load().AllowedSid;
        if (!string.IsNullOrWhiteSpace(persisted))
        {
            return persisted.Trim();
        }

        return WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("Cannot determine the allowed SID.");
    }

    public static string Milestone => ProductMilestone.Current;
}
