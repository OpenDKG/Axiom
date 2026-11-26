// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Principal;
using Axiom.Contracts;
using Axiom.Contracts.Protection;
using Axiom.Core.Protection;
using Axiom.Infrastructure.Windows.Ipc;

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
    public static AllowedPipeSid ResolveAllowedSid()
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
    /// A refused SID falls back to the service's own account, which grants nobody else access. A
    /// well-formed SID that Windows cannot resolve is marked pending, so the transport retries it.
    /// </summary>
    internal static AllowedPipeSid ResolveAllowedSid(
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
            return new AllowedPipeSid(currentSid);
        }

        var wellFormed = AccountSid.IsWellFormed(candidate);
        var use = wellFormed ? lookup(candidate) : null;
        if (use == SidNameUse.User)
        {
            return new AllowedPipeSid(candidate);
        }

        var pending = wellFormed && use is null;
        var source = fromEnvironment ? "AXIOM_ALLOWED_SID" : store.FilePath;
        reportRefusal(pending
            ? $"pipe: Windows cannot resolve the allowed SID from {source} yet. Only the service account can " +
              "connect until it resolves to a user."
            : $"pipe: refused the allowed SID from {source} because it is not a user account. Only the " +
              "service account can connect until setup is re-run.");
        return new AllowedPipeSid(currentSid, pending);
    }
}
