// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;

namespace Axiom.Infrastructure.Linux.Nft;

/// <summary>One blocked (or traced) packet as reported by <c>nft monitor trace</c>, joined by trace id.</summary>
public sealed record NftTraceEvent(
    string TraceId,
    string Chain,
    string Protocol,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string Verdict,
    Guid? RuleId);

/// <summary>
/// Parses the text stream of <c>nft monitor trace</c> (one line per trace record) into
/// <see cref="NftTraceEvent"/>s. Block rules carry <c>meta nftrace set 1</c> (and only those, so
/// allowed flows cost nothing), which makes the kernel emit, per packet, a <c>packet:</c> line with
/// the headers and a <c>rule</c> line with the verdict and the rule's comment. The two are joined by
/// trace id; a packet whose rule line never arrives is dropped after <see cref="MaxPending"/> others.
/// </summary>
public sealed class NftTraceParser
{
    public const int MaxPending = 256;

    private readonly Dictionary<string, Packet> _pending = new(StringComparer.Ordinal);
    private readonly Queue<string> _order = new();

    private sealed record Packet(string Chain, string Protocol, string Saddr, int Sport, string Daddr, int Dport);

    /// <summary>Feeds one line; returns the completed event when this line was a verdict for a known packet.</summary>
    public NftTraceEvent? Feed(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return null;
        }

        var tokens = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        // trace id <hex> <family> <table> <chain> packet: ... | rule ... (verdict X) | policy X | verdict X
        if (tokens.Length < 7 || tokens[0] != "trace" || tokens[1] != "id" || tokens[4] != NftRuleCompiler.TableName)
        {
            return null;
        }

        var traceId = tokens[2];
        var chain = tokens[5];
        var kind = tokens[6];
        if (kind == "packet:")
        {
            Remember(traceId, ParsePacket(chain, tokens));
            return null;
        }

        if (!_pending.Remove(traceId, out var packet))
        {
            return null;
        }

        var verdict = Verdict(line);
        Guid? ruleId = null;
        var comment = line.IndexOf("comment \"", StringComparison.Ordinal);
        if (comment >= 0)
        {
            var start = comment + "comment \"".Length;
            var end = line.IndexOf('"', start);
            if (end > start && NftTable.TryParseComment(line[start..end], out var id, out _))
            {
                ruleId = id;
            }
        }

        var inbound = chain == NftRuleCompiler.InputChain;
        return new NftTraceEvent(
            traceId,
            chain,
            packet.Protocol,
            inbound ? packet.Daddr : packet.Saddr,
            inbound ? packet.Dport : packet.Sport,
            inbound ? packet.Saddr : packet.Daddr,
            inbound ? packet.Sport : packet.Dport,
            verdict,
            ruleId);
    }

    private void Remember(string traceId, Packet packet)
    {
        if (_pending.TryAdd(traceId, packet))
        {
            _order.Enqueue(traceId);
        }

        while (_order.Count > MaxPending)
        {
            _pending.Remove(_order.Dequeue());
        }
    }

    private static Packet ParsePacket(string chain, string[] tokens)
    {
        var protocol = "other";
        var saddr = string.Empty;
        var daddr = string.Empty;
        var sport = 0;
        var dport = 0;
        for (var i = 7; i + 1 < tokens.Length; i++)
        {
            switch (tokens[i])
            {
                case "ip" or "ip6" when i + 2 < tokens.Length && tokens[i + 1] == "saddr":
                    saddr = tokens[i + 2];
                    break;
                case "ip" or "ip6" when i + 2 < tokens.Length && tokens[i + 1] == "daddr":
                    daddr = tokens[i + 2];
                    break;
                case "ip" when i + 2 < tokens.Length && tokens[i + 1] == "protocol":
                    protocol = tokens[i + 2];
                    break;
                case "ip6" when i + 2 < tokens.Length && tokens[i + 1] == "nexthdr":
                    protocol = tokens[i + 2];
                    break;
                case "tcp" or "udp" when i + 2 < tokens.Length && tokens[i + 1] == "sport":
                    protocol = tokens[i];
                    sport = Port(tokens[i + 2]);
                    break;
                case "tcp" or "udp" when i + 2 < tokens.Length && tokens[i + 1] == "dport":
                    protocol = tokens[i];
                    dport = Port(tokens[i + 2]);
                    break;
                default:
                    break;
            }
        }

        return new Packet(chain, protocol, saddr, sport, daddr, dport);
    }

    private static string Verdict(string line)
    {
        var open = line.LastIndexOf("(verdict ", StringComparison.Ordinal);
        if (open >= 0)
        {
            var close = line.IndexOf(')', open);
            var verdict = close > open ? line[(open + 9)..close] : line[(open + 9)..];
            return verdict is "drop" or "reject" ? "block" : verdict == "accept" ? "allow" : verdict;
        }

        if (line.Contains(" reject", StringComparison.Ordinal) || line.EndsWith(" drop", StringComparison.Ordinal))
        {
            return "block";
        }

        return line.EndsWith(" accept", StringComparison.Ordinal) ? "allow" : "unknown";
    }

    private static int Port(string text) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port <= 65535 ? port : 0;
}
