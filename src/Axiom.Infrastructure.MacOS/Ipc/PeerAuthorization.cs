// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Core.Protection;
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.MacOS.Ipc;

/// <summary>
/// Outcome of the caller check on the daemon socket, one flag per layer: <see cref="Allowed"/>
/// gates the connection (public health commands), <see cref="CanReadPrivate"/> gates commands that
/// disclose machine-wide activity, <see cref="CanWrite"/> gates commands that change machine state.
/// Per-command capability is decided by <see cref="IpcCommandAccess"/> on top of these flags.
/// </summary>
public sealed record PeerDecision(
    bool Allowed,
    string Actor,
    string Reason,
    bool CanWrite = true,
    string? WriteDenialReason = null,
    bool CanReadPrivate = true,
    string? ReadDenialReason = null)
{
    /// <summary>The dispatcher-side identity for this peer.</summary>
    public IpcCaller ToCaller() => new(Actor, CanWrite, WriteDenialReason, CanReadPrivate, ReadDenialReason);
}

/// <summary>
/// Who may read private data and change machine-wide state over the socket: the uid recorded at
/// install time (<see cref="ProtectionSettings.AllowedUid"/>) and, when the explicit
/// <see cref="ProtectionSettings.AllowAdminGroupWrites"/> policy is on, members of the <c>admin</c>
/// group. <paramref name="IsAdminMember"/> answers group membership for a uid (getgrouplist).
/// </summary>
public sealed record PeerPolicy(uint? OwnerUid, bool AdminGroupMayWrite, Func<uint, bool> IsAdminMember)
{
    public const string AdminGroup = "admin";

    /// <summary>No owner, no admin group: only root reads private data or writes.</summary>
    public static PeerPolicy RootOnlyWrites { get; } = new(null, false, _ => false);

    public static PeerPolicy FromSettings(ProtectionSettings settings, Func<uint, bool> isAdminMember)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(isAdminMember);
        return new PeerPolicy(settings.AllowedUid, settings.AllowAdminGroupWrites, isAdminMember);
    }
}

/// <summary>
/// Who may talk to the daemon over <c>/var/run/axiom/axiom.sock</c>, and what they may ask. The
/// socket is world connectable (0666): macOS has no group that contains "the user who installed
/// Axiom" and the installing user is not necessarily an administrator, so a 0660 socket with a
/// root-owned group would lock the desktop app out; instead every accepted connection is identified
/// with <c>getpeereid</c> before a byte is read and the decision below is enforced per command by the
/// shared dispatcher. Layers (docs/MACOS_ARCHITECTURE.md §5.4):
/// <list type="bullet">
/// <item>Connection: root and regular console users (uid ≥ 501, the macOS range for local
/// accounts) may connect; system/daemon accounts (1..500), <c>nobody</c> and a peer whose
/// credentials cannot be read are closed without a reply.</item>
/// <item>Private read (snapshot, live events, history, DNS status, diagnostics, settings) and write
/// (rules, Axiom Shield, Privacy Shield, threat sharing, recovery): root (documented privileged
/// policy: root owns the daemon, its data directory and the rules file), the installing user, and
/// members of <c>admin</c> only under the explicit <c>AllowAdminGroupWrites</c> policy.</item>
/// <item>Any other local account gets the public health commands (<c>serviceHealth</c> redacted,
/// <c>capabilities</c>) and <c>unauthorized</c> for everything else, so a second standard user
/// cannot read the first user's traffic history or change the machine.</item>
/// </list>
/// The policy is pure (<see cref="Decide(uint?, PeerPolicy?)"/>, <see cref="Permits"/>) so the
/// Linux port can reuse it unchanged over <c>SO_PEERCRED</c>. The actor recorded in the audit trail
/// is <c>uid:N</c>.
/// </summary>
public static class PeerAuthorization
{
    public const uint RootUid = 0;

    public const uint FirstConsoleUid = 501;

    /// <summary>macOS <c>nobody</c> (-2).</summary>
    public const uint NobodyUid = 4294967294;

    public const uint UnknownUid = uint.MaxValue;

    public static string ActorFor(uint uid) => "uid:" + uid.ToString(CultureInfo.InvariantCulture);

    /// <summary>Decision without an install record: only root is privileged (safe default for tools and tests).</summary>
    public static PeerDecision Decide(uint? uid) => Decide(uid, null);

    /// <summary>
    /// Connection-level decision plus the private-read and write permissions under
    /// <paramref name="policy"/> (null = <see cref="PeerPolicy.RootOnlyWrites"/>).
    /// </summary>
    public static PeerDecision Decide(uint? uid, PeerPolicy? policy)
    {
        policy ??= PeerPolicy.RootOnlyWrites;

        if (uid is not { } value || value == UnknownUid)
        {
            return new PeerDecision(false, "uid:unknown", "The peer credentials could not be read.", false, "unknown peer", false, "unknown peer");
        }

        if (value == RootUid)
        {
            return new PeerDecision(true, ActorFor(value), "root");
        }

        if (value == NobodyUid)
        {
            return new PeerDecision(false, ActorFor(value), "The nobody account may not use the daemon.", false, "nobody", false, "nobody");
        }

        if (value < FirstConsoleUid)
        {
            return new PeerDecision(false, ActorFor(value), "System accounts below uid 501 may not use the daemon.", false, "system account", false, "system account");
        }

        if (policy.OwnerUid == value)
        {
            return new PeerDecision(true, ActorFor(value), "installing user");
        }

        if (policy.AdminGroupMayWrite && policy.IsAdminMember(value))
        {
            return new PeerDecision(true, ActorFor(value), "admin group member (AllowAdminGroupWrites)");
        }

        return new PeerDecision(
            true,
            ActorFor(value),
            "console user (public health only)",
            false,
            WriteDenialMessage(value, policy),
            false,
            ReadDenialMessage(value, policy));
    }

    /// <summary>Pure per-command answer for a (uid, policy, command class) triple.</summary>
    public static bool Permits(uint? uid, PeerPolicy? policy, IpcCommandClass commandClass)
    {
        var decision = Decide(uid, policy);
        return decision.Allowed && decision.ToCaller().Permits(commandClass);
    }

    public static string WriteDenialMessage(uint uid, PeerPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return $"This command changes machine-wide settings and is only allowed for {AllowedCallers(policy)}; " +
               $"uid {uid.ToString(CultureInfo.InvariantCulture)} may only read public service health.";
    }

    public static string ReadDenialMessage(uint uid, PeerPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return $"This command discloses machine-wide activity and is only allowed for {AllowedCallers(policy)}; " +
               $"uid {uid.ToString(CultureInfo.InvariantCulture)} may only read public service health.";
    }

    private static string AllowedCallers(PeerPolicy policy)
    {
        var allowed = policy.OwnerUid is { } owner
            ? $"root, the user who installed Axiom (uid {owner.ToString(CultureInfo.InvariantCulture)})"
            : "root";
        if (policy.AdminGroupMayWrite)
        {
            allowed += " and members of the admin group";
        }

        return allowed;
    }

    public const string Description =
        "connect: root and console users (uid 0 or uid >= 501, checked with getpeereid); " +
        "private reads and writes: root, the installing user and (policy) the admin group; other users: public health only";
}
