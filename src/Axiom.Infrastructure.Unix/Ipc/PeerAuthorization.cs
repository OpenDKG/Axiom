// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Core.Protection;

namespace Axiom.Infrastructure.Unix.Ipc;

/// <summary>
/// Outcome of the caller check on the daemon socket. <see cref="Allowed"/> gates the connection
/// (read-only commands); <see cref="CanWrite"/> gates commands that change machine state.
/// </summary>
public sealed record PeerDecision(bool Allowed, string Actor, string Reason, bool CanWrite = true, string? WriteDenialReason = null);

/// <summary>
/// The local account conventions of one Unix flavour: where regular (console) users start, which
/// uid is <c>nobody</c>, which groups count as administrators for IPC writes and how the peer
/// credentials are read. macOS: 501, -2, <c>admin</c>, <c>getpeereid</c>. Linux: 1000, 65534,
/// <c>axiom</c>/<c>sudo</c>/<c>wheel</c>, <c>SO_PEERCRED</c>.
/// </summary>
public sealed record UnixAccountRange(uint FirstUserUid, uint NobodyUid, IReadOnlyList<string> AdminGroups, string CredentialSource)
{
    public static UnixAccountRange MacOS { get; } = new(501, 4294967294, ["admin"], "getpeereid");

    public static UnixAccountRange Linux { get; } = new(1000, 65534, ["axiom", "sudo", "wheel"], "SO_PEERCRED");

    /// <summary>The range of the running OS (Linux everywhere but macOS hosts).</summary>
    public static UnixAccountRange Current => OperatingSystem.IsMacOS() ? MacOS : Linux;

    /// <summary>"the admin group" / "the axiom, sudo or wheel groups" for messages.</summary>
    public string AdminGroupsText => AdminGroups.Count == 1
        ? $"the {AdminGroups[0]} group"
        : "the " + string.Join(", ", AdminGroups.Take(AdminGroups.Count - 1)) + " or " + AdminGroups[^1] + " groups";

    /// <summary>True when <paramref name="uid"/> is a regular local user (not root, system or nobody).</summary>
    public bool IsRegularUser(uint uid) => uid >= FirstUserUid && uid != NobodyUid && uid != PeerAuthorization.UnknownUid;

    public string Describe() =>
        $"root and console users (uid 0 or uid >= {FirstUserUid.ToString(CultureInfo.InvariantCulture)}, checked with {CredentialSource}); " +
        $"writes: root, the installing user and {AdminGroupsText}";
}

/// <summary>
/// Who may change machine-wide state over the socket: the uid recorded at install time
/// (<see cref="ProtectionSettings.AllowedUid"/>) and, when enabled, members of the admin
/// group(s). <paramref name="IsAdminMember"/> answers group membership for a uid (getgrouplist).
/// </summary>
public sealed record PeerPolicy(uint? OwnerUid, bool AdminGroupMayWrite, Func<uint, bool> IsAdminMember)
{
    /// <summary>The macOS administrator group.</summary>
    public const string AdminGroup = "admin";

    /// <summary>Read-only for everyone but root: no owner, no admin group.</summary>
    public static PeerPolicy RootOnlyWrites { get; } = new(null, false, _ => false);

    public static PeerPolicy FromSettings(ProtectionSettings settings, Func<uint, bool> isAdminMember)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(isAdminMember);
        return new PeerPolicy(settings.AllowedUid, settings.AllowAdminGroupWrites, isAdminMember);
    }

    /// <summary>
    /// Production policy for <paramref name="range"/>: membership in any of its admin groups
    /// (<see cref="Interop.UnixGroups"/>) grants writes when the setting allows it.
    /// </summary>
    public static PeerPolicy FromSettings(ProtectionSettings settings, UnixAccountRange range)
    {
        ArgumentNullException.ThrowIfNull(range);
        return FromSettings(settings, member => range.AdminGroups.Any(group => Interop.UnixGroups.IsMember(member, group)));
    }
}

/// <summary>
/// Who may talk to the daemon over the Unix socket (<c>/var/run/axiom/axiom.sock</c> on macOS,
/// <c>/run/axiom/axiom.sock</c> on Linux). The socket is world connectable (0666) like a Windows
/// pipe with an explicit DACL; the decision is made on the peer uid: root and regular console users
/// (uid at or above the platform's first user uid) may connect and read; system/daemon accounts,
/// <c>nobody</c> and an unknown peer are rejected. Write commands (rules, protection, Privacy
/// Shield configuration, threat sharing) are limited to root, the installing user and optionally
/// the platform's admin group(s), mirroring the single persisted SID on Windows. The actor
/// recorded in the audit trail is <c>uid:N</c>.
/// </summary>
public static class PeerAuthorization
{
    public const uint RootUid = 0;

    /// <summary>First regular user uid on macOS (<see cref="UnixAccountRange.MacOS"/>).</summary>
    public const uint FirstConsoleUid = 501;

    /// <summary>macOS <c>nobody</c> (-2).</summary>
    public const uint NobodyUid = 4294967294;

    public const uint UnknownUid = uint.MaxValue;

    public static string ActorFor(uint uid) => "uid:" + uid.ToString(CultureInfo.InvariantCulture);

    /// <summary>Connection-level decision only; every connected peer may write (legacy/test use).</summary>
    public static PeerDecision Decide(uint? uid) => Decide(uid, null, UnixAccountRange.MacOS);

    /// <summary>
    /// Connection-level decision plus the write permission under <paramref name="policy"/>
    /// (null = every connected peer may write), macOS account conventions.
    /// </summary>
    public static PeerDecision Decide(uint? uid, PeerPolicy? policy) => Decide(uid, policy, UnixAccountRange.MacOS);

    /// <summary>Connection-level decision plus the write permission for one account range.</summary>
    public static PeerDecision Decide(uint? uid, PeerPolicy? policy, UnixAccountRange range)
    {
        ArgumentNullException.ThrowIfNull(range);

        if (uid is not { } value || value == UnknownUid)
        {
            return new PeerDecision(false, "uid:unknown", "The peer credentials could not be read.", false, "unknown peer");
        }

        if (value == RootUid)
        {
            return new PeerDecision(true, ActorFor(value), "root");
        }

        if (value == range.NobodyUid)
        {
            return new PeerDecision(false, ActorFor(value), "The nobody account may not use the daemon.", false, "nobody");
        }

        if (value < range.FirstUserUid)
        {
            return new PeerDecision(
                false,
                ActorFor(value),
                $"System accounts below uid {range.FirstUserUid.ToString(CultureInfo.InvariantCulture)} may not use the daemon.",
                false,
                "system account");
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
            WriteDenialMessage(value, policy, range));
    }

    public static string WriteDenialMessage(uint uid, PeerPolicy policy) => WriteDenialMessage(uid, policy, UnixAccountRange.MacOS);

    public static string WriteDenialMessage(uint uid, PeerPolicy policy, UnixAccountRange range)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(range);
        var allowed = policy.OwnerUid is { } owner
            ? $"root, the user who installed Axiom (uid {owner.ToString(CultureInfo.InvariantCulture)})"
            : "root";
        if (policy.AdminGroupMayWrite)
        {
            allowed += " and members of " + range.AdminGroupsText;
        }

        return $"This command changes machine-wide settings and is only allowed for {allowed}; " +
               $"uid {uid.ToString(CultureInfo.InvariantCulture)} may only read.";
    }

    /// <summary>The macOS description (kept for the launchd daemon's startup log).</summary>
    public const string Description =
        "root and console users (uid 0 or uid >= 501, checked with getpeereid); writes: root, the installing user and the admin group";
}
