// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Core.Protection;
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.Unix.Ipc;

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
        $"connect: root and console users (uid 0 or uid >= {FirstUserUid.ToString(CultureInfo.InvariantCulture)}, checked with {CredentialSource}); " +
        $"private reads and writes: root, the installing user and (policy) {AdminGroupsText}; other users: public health only";
}

/// <summary>
/// Who may read private data and change machine-wide state over the socket: the uid recorded at
/// install time (<see cref="ProtectionSettings.AllowedUid"/>) and, when the explicit
/// <see cref="ProtectionSettings.AllowAdminGroupWrites"/> policy is on, members of the admin
/// group(s). <paramref name="IsAdminMember"/> answers group membership for a uid (getgrouplist).
/// </summary>
public sealed record PeerPolicy(uint? OwnerUid, bool AdminGroupMayWrite, Func<uint, bool> IsAdminMember)
{
    /// <summary>The macOS administrator group.</summary>
    public const string AdminGroup = "admin";

    /// <summary>No owner, no admin group: only root reads private data or writes.</summary>
    public static PeerPolicy RootOnlyWrites { get; } = new(null, false, _ => false);

    public static PeerPolicy FromSettings(ProtectionSettings settings, Func<uint, bool> isAdminMember)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(isAdminMember);
        return new PeerPolicy(settings.AllowedUid, settings.AllowAdminGroupWrites, isAdminMember);
    }

    /// <summary>
    /// Production policy for <paramref name="range"/>: membership in any of its admin groups
    /// (<see cref="Interop.UnixGroups"/>) grants private reads and writes when the setting allows it.
    /// </summary>
    public static PeerPolicy FromSettings(ProtectionSettings settings, UnixAccountRange range)
    {
        ArgumentNullException.ThrowIfNull(range);
        return FromSettings(settings, member => range.AdminGroups.Any(group => Interop.UnixGroups.IsMember(member, group)));
    }
}

/// <summary>
/// Who may talk to the daemon over the Unix socket (<c>/var/run/axiom/axiom.sock</c> on macOS,
/// <c>/run/axiom/axiom.sock</c> on Linux), and what they may ask. The socket is world connectable
/// (0666): neither platform has a group that contains "the user who installed Axiom" and the
/// installing user is not necessarily an administrator, so a 0660 socket with a root-owned group
/// would lock the desktop app out; instead every accepted connection is identified by its peer uid
/// (<c>getpeereid</c> / <c>SO_PEERCRED</c>, kernel-set) before a byte is read and the decision
/// below is enforced per command by the shared dispatcher. Layers (docs/MACOS_ARCHITECTURE.md §5.4,
/// docs/LINUX_ARCHITECTURE.md authorization table):
/// <list type="bullet">
/// <item>Connection: root and regular console users (uid at or above the platform's first user
/// uid) may connect; system/daemon accounts, <c>nobody</c> and a peer whose credentials cannot be
/// read are closed without a reply.</item>
/// <item>Private read (snapshot, live events, history, DNS status, diagnostics, settings) and write
/// (rules, Axiom Shield, Privacy Shield, threat sharing, recovery): root (documented privileged
/// policy: root owns the daemon, its data directory and the rules), the installing user, and
/// members of the platform's admin group(s) only under the explicit <c>AllowAdminGroupWrites</c>
/// policy (default on; the same switch covers private reads on both platforms).</item>
/// <item>Any other local account gets the public health commands (<c>serviceHealth</c> redacted,
/// <c>capabilities</c>) and <c>unauthorized</c> for everything else, so a second standard user
/// cannot read the first user's traffic history or change the machine.</item>
/// </list>
/// The policy is pure (<see cref="Decide(uint?, PeerPolicy?, UnixAccountRange)"/>, <see cref="Permits(uint?, PeerPolicy?, IpcCommandClass, UnixAccountRange)"/>)
/// so it is shared between macOS and Linux and unit-testable without a socket. The actor recorded
/// in the audit trail is <c>uid:N</c>.
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

    /// <summary>Decision without an install record: only root is privileged (safe default for tools and tests), macOS conventions.</summary>
    public static PeerDecision Decide(uint? uid) => Decide(uid, null, UnixAccountRange.MacOS);

    /// <summary>
    /// Connection-level decision plus the private-read and write permissions under
    /// <paramref name="policy"/> (null = <see cref="PeerPolicy.RootOnlyWrites"/>), macOS account conventions.
    /// </summary>
    public static PeerDecision Decide(uint? uid, PeerPolicy? policy) => Decide(uid, policy, UnixAccountRange.MacOS);

    /// <summary>
    /// Connection-level decision plus the private-read and write permissions under
    /// <paramref name="policy"/> (null = <see cref="PeerPolicy.RootOnlyWrites"/>) for one account range.
    /// </summary>
    public static PeerDecision Decide(uint? uid, PeerPolicy? policy, UnixAccountRange range)
    {
        ArgumentNullException.ThrowIfNull(range);
        policy ??= PeerPolicy.RootOnlyWrites;

        if (uid is not { } value || value == UnknownUid)
        {
            return new PeerDecision(false, "uid:unknown", "The peer credentials could not be read.", false, "unknown peer", false, "unknown peer");
        }

        if (value == RootUid)
        {
            return new PeerDecision(true, ActorFor(value), "root");
        }

        if (value == range.NobodyUid)
        {
            return new PeerDecision(false, ActorFor(value), "The nobody account may not use the daemon.", false, "nobody", false, "nobody");
        }

        if (value < range.FirstUserUid)
        {
            var reason = $"System accounts below uid {range.FirstUserUid.ToString(CultureInfo.InvariantCulture)} may not use the daemon.";
            return new PeerDecision(false, ActorFor(value), reason, false, "system account", false, "system account");
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
            WriteDenialMessage(value, policy, range),
            false,
            ReadDenialMessage(value, policy, range));
    }

    /// <summary>Pure per-command answer for a (uid, policy, command class) triple, macOS conventions.</summary>
    public static bool Permits(uint? uid, PeerPolicy? policy, IpcCommandClass commandClass) =>
        Permits(uid, policy, commandClass, UnixAccountRange.MacOS);

    /// <summary>Pure per-command answer for a (uid, policy, command class) triple.</summary>
    public static bool Permits(uint? uid, PeerPolicy? policy, IpcCommandClass commandClass, UnixAccountRange range)
    {
        var decision = Decide(uid, policy, range);
        return decision.Allowed && decision.ToCaller().Permits(commandClass);
    }

    public static string WriteDenialMessage(uint uid, PeerPolicy policy) => WriteDenialMessage(uid, policy, UnixAccountRange.MacOS);

    public static string WriteDenialMessage(uint uid, PeerPolicy policy, UnixAccountRange range)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(range);
        return $"This command changes machine-wide settings and is only allowed for {AllowedCallers(policy, range)}; " +
               $"uid {uid.ToString(CultureInfo.InvariantCulture)} may only read public service health.";
    }

    public static string ReadDenialMessage(uint uid, PeerPolicy policy) => ReadDenialMessage(uid, policy, UnixAccountRange.MacOS);

    public static string ReadDenialMessage(uint uid, PeerPolicy policy, UnixAccountRange range)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(range);
        return $"This command discloses machine-wide activity and is only allowed for {AllowedCallers(policy, range)}; " +
               $"uid {uid.ToString(CultureInfo.InvariantCulture)} may only read public service health.";
    }

    private static string AllowedCallers(PeerPolicy policy, UnixAccountRange range)
    {
        var allowed = policy.OwnerUid is { } owner
            ? $"root, the user who installed Axiom (uid {owner.ToString(CultureInfo.InvariantCulture)})"
            : "root";
        if (policy.AdminGroupMayWrite)
        {
            allowed += " and members of " + range.AdminGroupsText;
        }

        return allowed;
    }

    /// <summary>The macOS description (kept for the launchd daemon's startup log).</summary>
    public const string Description =
        "connect: root and console users (uid 0 or uid >= 501, checked with getpeereid); " +
        "private reads and writes: root, the installing user and (policy) the admin group; other users: public health only";
}
