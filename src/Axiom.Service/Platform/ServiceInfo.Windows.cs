// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Principal;
using Axiom.Contracts;
using Axiom.Contracts.Protection;
using Axiom.Core.Protection;

namespace Axiom.Service;

/// <summary>Windows-only service identity (net10.0-windows target).</summary>
public static partial class ServiceInfo
{
    /// <summary>
    /// SID allowed to call the pipe. An installed service persists the interactive user's SID in the
    /// shield state; AXIOM_ALLOWED_SID overrides it, and console development falls back to the
    /// current user. The pipe ACL grants whatever this returns, so a configured or persisted SID is
    /// checked again here and refused unless it names a user account.
    /// </summary>
    public static string ResolveAllowedSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var current = identity.User?.Value
            ?? throw new InvalidOperationException("Cannot determine the allowed SID.");
        var configured = Environment.GetEnvironmentVariable("AXIOM_ALLOWED_SID")
                         ?? Environment.GetEnvironmentVariable(LegacyIdentity.ProductName + "_ALLOWED_SID");
        return ResolveAllowedSid(
            configured,
            new ProtectionSettingsStore(),
            current,
            AccountSid.Lookup,
            message =>
            {
                Console.Error.WriteLine(message);
                ServiceInstallLog.Write(message);
            });
    }

    /// <summary>
    /// A refused SID falls back to the service's own account, which grants nobody else access.
    /// </summary>
    internal static string ResolveAllowedSid(
        string? configuredSid,
        ProtectionSettingsStore store,
        string currentSid,
        Func<string, SidNameUse?> lookup,
        Action<string> reportRefusal)
    {
        var fromEnvironment = !string.IsNullOrWhiteSpace(configuredSid);
        var candidate = (fromEnvironment ? configuredSid : store.Load().AllowedSid)?.Trim();
        if (string.IsNullOrEmpty(candidate) ||
            string.Equals(candidate, currentSid, StringComparison.OrdinalIgnoreCase))
        {
            return currentSid;
        }

        if (AccountSid.IsUser(candidate, lookup))
        {
            return candidate;
        }

        var source = fromEnvironment ? "AXIOM_ALLOWED_SID" : store.FilePath;
        reportRefusal(
            $"pipe: refused the allowed SID from {source} because it is not a user account that Windows can " +
            "resolve. Only the service account can connect until setup is re-run.");
        return currentSid;
    }
}
