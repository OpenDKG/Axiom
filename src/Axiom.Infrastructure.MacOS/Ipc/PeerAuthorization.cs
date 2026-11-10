// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;

namespace Axiom.Infrastructure.MacOS.Ipc;

/// <summary>Outcome of the caller check on the daemon socket.</summary>
public sealed record PeerDecision(bool Allowed, string Actor, string Reason);

/// <summary>
/// Who may talk to the daemon over <c>/var/run/axiom/axiom.sock</c>. The socket is world
/// connectable (0666) like a Windows pipe with an explicit DACL; the decision is made on the peer
/// uid from <c>getpeereid</c>: root and regular console users (uid &gt;= 501, the macOS range for
/// local accounts) are allowed; system/daemon accounts (1..500), <c>nobody</c> and an unknown peer
/// are rejected. The actor recorded in the audit trail is <c>uid:N</c>.
/// </summary>
public static class PeerAuthorization
{
    public const uint RootUid = 0;

    public const uint FirstConsoleUid = 501;

    /// <summary>macOS <c>nobody</c> (-2).</summary>
    public const uint NobodyUid = 4294967294;

    public const uint UnknownUid = uint.MaxValue;

    public static string ActorFor(uint uid) => "uid:" + uid.ToString(CultureInfo.InvariantCulture);

    public static PeerDecision Decide(uint? uid)
    {
        if (uid is not { } value || value == UnknownUid)
        {
            return new PeerDecision(false, "uid:unknown", "The peer credentials could not be read.");
        }

        if (value == RootUid)
        {
            return new PeerDecision(true, ActorFor(value), "root");
        }

        if (value == NobodyUid)
        {
            return new PeerDecision(false, ActorFor(value), "The nobody account may not use the daemon.");
        }

        if (value >= FirstConsoleUid)
        {
            return new PeerDecision(true, ActorFor(value), "console user");
        }

        return new PeerDecision(false, ActorFor(value), "System accounts below uid 501 may not use the daemon.");
    }

    public const string Description = "root and console users (uid 0 or uid >= 501, checked with getpeereid)";
}
