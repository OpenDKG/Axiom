// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace LocalFirewall.Infrastructure.Windows.Ipc;

/// <summary>
/// Explicit DACL for the service pipe: only the service account and one authorized interactive
/// SID may connect. Network, anonymous and guest logons are denied so the pipe cannot be reached
/// over SMB even if the SID were reused remotely.
/// </summary>
public static class PipeSecurityFactory
{
    public static PipeSecurity Create(string allowedSid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(allowedSid);

        var currentUser = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Current Windows identity has no user SID.");

        var allowed = new SecurityIdentifier(allowedSid);

        var security = new PipeSecurity();
        security.SetOwner(currentUser);

        // Deny ACEs first so canonical order gives them precedence over the allow entries.
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Deny));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AnonymousSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Deny));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinGuestsSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Deny));

        security.AddAccessRule(new PipeAccessRule(
            currentUser,
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        if (!allowed.Equals(currentUser))
        {
            security.AddAccessRule(new PipeAccessRule(
                allowed,
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));
        }

        return security;
    }
}
