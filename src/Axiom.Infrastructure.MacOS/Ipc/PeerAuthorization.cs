// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Core.Protection;

namespace Axiom.Infrastructure.MacOS.Ipc;

/// <summary>
/// Outcome of the caller check on the daemon socket. <see cref="Allowed"/> gates the connection
/// (read-only commands); <see cref="CanWrite"/> gates commands that change machine state.
/// </summary>
public sealed record PeerDecision(bool Allowed, string Actor, string Reason, bool CanWrite = true, string? WriteDenialReason = null);

/// <summary>
/// Who may change machine-wide state over the socket: the uid recorded at install time
/// (<see cref="ProtectionSettings.AllowedUid"/>) and, when enabled, members of the <c>admin</c>
/// group. <paramref name="IsAdminMember"/> answers group membership for a uid (getgrouplist).
/// </summary>
public sealed record PeerPolicy(uint? OwnerUid, bool AdminGroupMayWrite, Func<uint, bool> IsAdminMember)
{
    public const string AdminGroup = "admin";

    /// <summary>Read-only for everyone but root: no owner, no admin group.</summary>
    public static PeerPolicy RootOnlyWrites { get; } = new(null, false, _ => false);

    public static PeerPolicy FromSettings(ProtectionSettings settings, Func<uint, bool> isAdminMember)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(isAdminMember);
        return new PeerPolicy(settings.AllowedUid, settings.AllowAdminGroupWrites, isAdminMember);
    }
}

/// <summary>
/// Who may talk to the daemon over <c>/var/run/axiom/axiom.sock</c>. The socket is world
/// connectable (0666) like a Windows pipe with an explicit DACL; the decision is made on the peer
/// uid from <c>getpeereid</c>: root and regular console users (uid &gt;= 501, the macOS range for
/// local accounts) may connect and read; system/daemon accounts (1..500), <c>nobody</c> and an
/// unknown peer are rejected. Write commands (rules, protection, Privacy Shield configuration,
/// threat sharing) are limited to root, the installing user and optionally the <c>admin</c> group,
/// mirroring the single persisted SID on Windows. The actor recorded in the audit trail is <c>uid:N</c>.
/// </summary>
public static class PeerAuthorization
{
    public const uint RootUid = 0;

    public const uint FirstConsoleUid = 501;

    /// <summary>macOS <c>nobody</c> (-2).</summary>
    public const uint NobodyUid = 4294967294;

    public const uint UnknownUid = uint.MaxValue;

    public static string ActorFor(uint uid) => "uid:" + uid.ToString(CultureInfo.InvariantCulture);

    /// <summary>Connection-level decision only; every connected peer may write (legacy/test use).</summary>
    public static PeerDecision Decide(uint? uid) => Decide(uid, null);

    /// <summary>
    /// Connection-level decision plus the write permission under <paramref name="policy"/>
    /// (null = every connected peer may write).
    /// </summary>
    public static PeerDecision Decide(uint? uid, PeerPolicy? policy)
    {
        if (uid is not { } value || value == UnknownUid)
        {
            return new PeerDecision(false, "uid:unknown", "The peer credentials could not be read.", false, "unknown peer");
        }

        if (value == RootUid)
        {
            return new PeerDecision(true, ActorFor(value), "root");
        }

        if (value == NobodyUid)
        {
            return new PeerDecision(false, ActorFor(value), "The nobody account may not use the daemon.", false, "nobody");
        }

        if (value < FirstConsoleUid)
        {
            return new PeerDecision(false, ActorFor(value), "System accounts below uid 501 may not use the daemon.", false, "system account");
        }

        if (policy is null)
        {
            return new PeerDecision(true, ActorFor(value), "console user");
        }

        if (policy.OwnerUid == value)
        {
            return new PeerDecision(true, ActorFor(value), "installing user");
        }

        if (policy.AdminGroupMayWrite && policy.IsAdminMember(value))
        {
            return new PeerDecision(true, ActorFor(value), "admin group member");
        }

        return new PeerDecision(
            true,
            ActorFor(value),
            "console user (read-only)",
            false,
            WriteDenialMessage(value, policy));
    }

    public static string WriteDenialMessage(uint uid, PeerPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var allowed = policy.OwnerUid is { } owner
            ? $"root, the user who installed Axiom (uid {owner.ToString(CultureInfo.InvariantCulture)})"
            : "root";
        if (policy.AdminGroupMayWrite)
        {
            allowed += " and members of the admin group";
        }

        return $"This command changes machine-wide settings and is only allowed for {allowed}; " +
               $"uid {uid.ToString(CultureInfo.InvariantCulture)} may only read.";
    }

    public const string Description =
        "root and console users (uid 0 or uid >= 501, checked with getpeereid); writes: root, the installing user and the admin group";
}
