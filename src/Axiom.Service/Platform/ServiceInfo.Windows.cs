// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Principal;
using Axiom.Contracts;
using Axiom.Core.Protection;

namespace Axiom.Service;

/// <summary>Windows-only service identity (net10.0-windows target).</summary>
public static partial class ServiceInfo
{
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
}
