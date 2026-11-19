// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Axiom.Contracts.Firewall;

namespace Axiom.Infrastructure.Linux.Nft;

/// <summary>One rule the compiler could not express in nftables, with the reason (never widened to "any").</summary>
public sealed record NftRejectedRule(Guid RuleId, string Reason);

/// <summary>One accepted rule: the nft rule lines emitted for it and the cgroup it is keyed on.</summary>
public sealed record NftCompiledRule(Guid RuleId, string CgroupPath, IReadOnlyList<string> Lines);

/// <summary>Result of compiling one generation: the atomic <c>nft -f</c> script plus the report.</summary>
public sealed record NftCompilation
{
    public required long Generation { get; init; }

    public required string Script { get; init; }

    public required IReadOnlyList<NftCompiledRule> Applied { get; init; }

    public required IReadOnlyList<NftRejectedRule> Rejected { get; init; }
}

/// <summary>Where a rule's application lives in the cgroup tree; the compiler asks this per app path.</summary>
public interface IAppCgroupResolver
{
    /// <summary>
    /// Returns the cgroup path (relative to the cgroup root, e.g. <c>axiom.slice/a-0123…</c>) that
    /// holds the app's processes, or null with a reason when the app cannot be keyed on a cgroup
    /// (unreachable binary, cgroup creation failed).
    /// </summary>
    bool TryResolve(string appPath, out string cgroupPath, out string reason);
}

/// <summary>
/// Turns Axiom <see cref="RuleSpec"/>s into one atomic nftables batch for <c>table inet axiom</c>.
/// <para>
/// Semantics follow docs/MACOS_ARCHITECTURE.md section 3.1 (Windows-like): an enabled matching block
/// rule wins over any allow rule (block rules are emitted first; nft stops at the first terminal
/// verdict), no match means accept (chain policy accept), loopback destinations are exempt unless a
/// rule names a loopback address (an early accept guard; the loopback part of such rules is emitted
/// above the guard), and anything the engine cannot express is rejected with a reason instead of
/// being widened.
/// </para>
/// <para>
/// Every rule is keyed on a daemon-owned cgroup via <c>socket cgroupv2 level N "path"</c> (level =
/// path depth). Block verdicts are <c>reject with tcp reset</c> for TCP and <c>drop</c> for UDP and
/// other protocols; block rules carry <c>meta nftrace set 1</c> so <c>nft monitor trace</c> reports
/// each blocked attempt (see <see cref="NftTraceParser"/>). Every rule has a <c>counter</c> and a
/// <c>comment "axiom:&lt;ruleId&gt;:&lt;n&gt;"</c> so hits can be attributed from <c>nft -j list</c>.
/// </para>
/// </summary>
public static class NftRuleCompiler
{
    public const string TableName = "axiom";
    public const string OutputChain = "axiom_out";
    public const string InputChain = "axiom_in";
    public const string CommentPrefix = "axiom:";

    private static readonly string[] WindowsAddressKeywords =
    [
        "localsubnet", "dns", "dhcp", "wins", "defaultgateway", "internet", "intranet", "ply2renders", "remoteaccess", "any",
    ];

    public static NftCompilation Compile(IEnumerable<RuleSpec> specs, long generation, IAppCgroupResolver cgroups)
    {
        ArgumentNullException.ThrowIfNull(specs);
        ArgumentNullException.ThrowIfNull(cgroups);

        var applied = new List<NftCompiledRule>();
        var rejected = new List<NftRejectedRule>();
        var outAbove = new List<string>();
        var outBelow = new List<string>();
        var inLines = new List<string>();

        // Block rules first so a block always wins over an allow of the same app (first match is final).
        var ordered = specs
            .Where(spec => spec.Enabled)
            .OrderBy(spec => spec.Action == FirewallAction.Block ? 0 : 1)
            .ThenBy(spec => spec.ManagedRuleId.ToString("D", CultureInfo.InvariantCulture), StringComparer.Ordinal)
            .ToList();

        foreach (var spec in ordered)
        {
            if (!TryCompileRule(spec, cgroups, out var compiled, out var reason, out var loopbackLines))
            {
                rejected.Add(new NftRejectedRule(spec.ManagedRuleId, reason));
                continue;
            }

            applied.Add(compiled);
            if (spec.Direction == FirewallDirection.Inbound)
            {
                inLines.AddRange(compiled.Lines);
            }
            else
            {
                outAbove.AddRange(loopbackLines);
                outBelow.AddRange(compiled.Lines.Except(loopbackLines, StringComparer.Ordinal));
            }
        }

        var script = new StringBuilder();
        script.Append("add table inet ").Append(TableName).Append('\n');
        script.Append("delete table inet ").Append(TableName).Append('\n');
        script.Append("table inet ").Append(TableName).Append(" {\n");
        script.Append("\tcomment \"axiom generation ").Append(generation.ToString(CultureInfo.InvariantCulture)).Append("\"\n");
        script.Append('\t').Append("chain ").Append(OutputChain).Append(" {\n");
        script.Append("\t\ttype filter hook output priority filter; policy accept;\n");
        foreach (var line in outAbove)
        {
            script.Append("\t\t").Append(line).Append('\n');
        }

        script.Append("\t\tip daddr 127.0.0.0/8 accept\n");
        script.Append("\t\tip6 daddr ::1 accept\n");
        foreach (var line in outBelow)
        {
            script.Append("\t\t").Append(line).Append('\n');
        }

        script.Append("\t}\n");
        script.Append('\t').Append("chain ").Append(InputChain).Append(" {\n");
        script.Append("\t\ttype filter hook input priority filter; policy accept;\n");
        script.Append("\t\tip saddr 127.0.0.0/8 accept\n");
        script.Append("\t\tip6 saddr ::1 accept\n");
        foreach (var line in inLines)
        {
            script.Append("\t\t").Append(line).Append('\n');
        }

        script.Append("\t}\n");
        script.Append("}\n");

        return new NftCompilation
        {
            Generation = generation,
            Script = script.ToString(),
            Applied = applied,
            Rejected = rejected,
        };
    }

    /// <summary>Validates a spec without a cgroup (pure); used by the adapter for early feedback.</summary>
    public static string? Validate(RuleSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.ManagedRuleId == Guid.Empty)
        {
            return "managed rule id is empty";
        }

        var appPath = spec.AppPath?.Trim() ?? string.Empty;
        if (appPath.Length == 0 || appPath == "*")
        {
            return "appPath is empty; Linux rules are keyed on one application cgroup";
        }

        if (!appPath.StartsWith('/'))
        {
            return $"appPath is not absolute: {appPath}";
        }

        if (spec.Profiles == FirewallProfile.None)
        {
            return "profiles is None: the rule applies to no network profile";
        }

        if (!NftPortSet.TryParse(spec.RemotePorts, out _, out var portError))
        {
            return portError;
        }

        if (!NftAddressSet.TryParse(spec.RemoteAddresses ?? [], out _, out var addressError))
        {
            return addressError;
        }

        return null;
    }

    private static bool TryCompileRule(
        RuleSpec spec,
        IAppCgroupResolver cgroups,
        out NftCompiledRule compiled,
        out string reason,
        out List<string> loopbackLines)
    {
        compiled = null!;
        loopbackLines = [];
        var validation = Validate(spec);
        if (validation is not null)
        {
            reason = validation;
            return false;
        }

        if (!cgroups.TryResolve(spec.AppPath.Trim(), out var cgroupPath, out reason))
        {
            return false;
        }

        _ = NftPortSet.TryParse(spec.RemotePorts, out var ports, out _);
        _ = NftAddressSet.TryParse(spec.RemoteAddresses ?? [], out var addresses, out _);

        var level = cgroupPath.Count(c => c == '/') + 1;
        var key = string.Create(CultureInfo.InvariantCulture, $"socket cgroupv2 level {level} \"{cgroupPath}\"");
        var id = spec.ManagedRuleId.ToString("D", CultureInfo.InvariantCulture);
        var inbound = spec.Direction == FirewallDirection.Inbound;
        var addressField = inbound ? "saddr" : "daddr";
        var portField = inbound ? "sport" : "dport";
        var lines = new List<string>();
        var n = 0;

        string Comment() => string.Create(CultureInfo.InvariantCulture, $"comment \"{CommentPrefix}{id}:{++n}\"");

        // Each (family, protocol) combination is one nft rule; a rule without addresses matches both families.
        var families = new List<(string? Family, string? Match, bool Loopback)>();
        if (addresses.IsAny)
        {
            families.Add((null, null, false));
        }
        else
        {
            if (addresses.V4.Count > 0)
            {
                families.Add(("ip", $"ip {addressField} {{ {string.Join(", ", addresses.V4)} }}", false));
            }

            if (addresses.V6.Count > 0)
            {
                families.Add(("ip6", $"ip6 {addressField} {{ {string.Join(", ", addresses.V6)} }}", false));
            }

            if (!inbound && addresses.LoopbackV4.Count > 0)
            {
                families.Add(("ip", $"ip {addressField} {{ {string.Join(", ", addresses.LoopbackV4)} }}", true));
            }

            if (!inbound && addresses.LoopbackV6)
            {
                families.Add(("ip6", $"ip6 {addressField} ::1", true));
            }
        }

        foreach (var (_, addressMatch, loopback) in families)
        {
            var protocols = spec.Protocol switch
            {
                NetworkProtocol.Tcp => new[] { "tcp" },
                NetworkProtocol.Udp => ["udp"],
                _ => ports.IsAny ? ["tcp", "udp", "other"] : ["tcp", "udp"],
            };

            foreach (var protocol in protocols)
            {
                var parts = new List<string>();
                parts.Add(protocol == "other" ? "meta l4proto != { tcp, udp }" : $"meta l4proto {protocol}");
                parts.Add(key);
                if (addressMatch is not null)
                {
                    parts.Add(addressMatch);
                }

                if (!ports.IsAny)
                {
                    parts.Add($"{protocol} {portField} {{ {ports.Text} }}");
                }

                parts.Add("counter");
                if (spec.Action == FirewallAction.Block)
                {
                    parts.Add("meta nftrace set 1");
                    parts.Add(protocol == "tcp" ? "reject with tcp reset" : "drop");
                }
                else
                {
                    parts.Add("accept");
                }

                parts.Add(Comment());
                var line = string.Join(' ', parts);
                lines.Add(line);
                if (loopback)
                {
                    loopbackLines.Add(line);
                }
            }
        }

        compiled = new NftCompiledRule(spec.ManagedRuleId, cgroupPath, lines);
        reason = string.Empty;
        return true;
    }

    /// <summary>Parsed <c>remotePorts</c> (<c>80,443,1000-2000</c>) as an nft anonymous-set body.</summary>
    public sealed record NftPortSet(bool IsAny, string Text)
    {
        public static bool TryParse(string? ports, out NftPortSet result, out string error)
        {
            error = string.Empty;
            if (string.IsNullOrWhiteSpace(ports) || ports.Trim() == "*")
            {
                result = new NftPortSet(true, string.Empty);
                return true;
            }

            var items = new List<string>();
            foreach (var raw in ports.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var dash = raw.IndexOf('-', StringComparison.Ordinal);
                if (dash < 0)
                {
                    if (!TryPort(raw, out var port))
                    {
                        error = $"invalid port '{raw}' (Windows port keywords are not supported on Linux)";
                        result = new NftPortSet(true, string.Empty);
                        return false;
                    }

                    items.Add(port.ToString(CultureInfo.InvariantCulture));
                    continue;
                }

                if (!TryPort(raw[..dash], out var from) || !TryPort(raw[(dash + 1)..], out var to) || from > to)
                {
                    error = $"invalid port range '{raw}'";
                    result = new NftPortSet(true, string.Empty);
                    return false;
                }

                items.Add(from == to
                    ? from.ToString(CultureInfo.InvariantCulture)
                    : string.Create(CultureInfo.InvariantCulture, $"{from}-{to}"));
            }

            if (items.Count == 0)
            {
                error = "remotePorts contains no port";
                result = new NftPortSet(true, string.Empty);
                return false;
            }

            result = new NftPortSet(false, string.Join(", ", items));
            return true;
        }

        private static bool TryPort(string text, out int port) =>
            int.TryParse(text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 0 and <= 65535;
    }

    /// <summary>
    /// Parsed <c>remoteAddresses</c>: IPs, CIDRs and <c>a-b</c> ranges, split by family and with the
    /// loopback entries (127.0.0.0/8, ::1) separated so they can be emitted above the loopback guard.
    /// <c>0.0.0.0/0</c> and <c>::/0</c> do not count as naming loopback (section 3.1).
    /// </summary>
    public sealed record NftAddressSet(
        bool IsAny,
        IReadOnlyList<string> V4,
        IReadOnlyList<string> V6,
        IReadOnlyList<string> LoopbackV4,
        bool LoopbackV6)
    {
        public static bool TryParse(IReadOnlyList<string> entries, out NftAddressSet result, out string error)
        {
            ArgumentNullException.ThrowIfNull(entries);
            error = string.Empty;
            var v4 = new List<string>();
            var v6 = new List<string>();
            var loopback4 = new List<string>();
            var loopback6 = false;
            var any = false;
            var seen = 0;
            foreach (var raw in entries)
            {
                var entry = raw?.Trim() ?? string.Empty;
                if (entry.Length == 0)
                {
                    continue;
                }

                seen++;
                if (entry == "*")
                {
                    any = true;
                    continue;
                }

                if (WindowsAddressKeywords.Contains(entry.ToLowerInvariant()))
                {
                    error = $"address keyword '{entry}' is Windows-only and not supported on Linux";
                    result = Any();
                    return false;
                }

                if (!TryParseEntry(entry, out var text, out var family, out var isLoopback))
                {
                    error = $"invalid address '{entry}' (IP, CIDR or a-b range expected; hostnames are not supported)";
                    result = Any();
                    return false;
                }

                if (family == AddressFamily.InterNetwork)
                {
                    (isLoopback ? loopback4 : v4).Add(text);
                }
                else if (isLoopback)
                {
                    loopback6 = true;
                }
                else
                {
                    v6.Add(text);
                }
            }

            if (seen == 0 || any)
            {
                result = Any();
                return true;
            }

            result = new NftAddressSet(false, v4, v6, loopback4, loopback6);
            return true;
        }

        private static NftAddressSet Any() => new(true, [], [], [], false);

        private static bool TryParseEntry(string entry, out string text, out AddressFamily family, out bool isLoopback)
        {
            text = string.Empty;
            family = AddressFamily.Unspecified;
            isLoopback = false;
            var slash = entry.IndexOf('/', StringComparison.Ordinal);
            if (slash >= 0)
            {
                if (!TryStrictAddress(entry[..slash], out var network) ||
                    !int.TryParse(entry[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix))
                {
                    return false;
                }

                var bits = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
                if (prefix < 0 || prefix > bits)
                {
                    return false;
                }

                var masked = Mask(network, prefix);
                family = network.AddressFamily;
                text = string.Create(CultureInfo.InvariantCulture, $"{masked}/{prefix}");
                isLoopback = prefix > 0 && IsLoopback(masked);
                return true;
            }

            var dash = entry.IndexOf('-', StringComparison.Ordinal);
            if (dash >= 0)
            {
                if (!TryStrictAddress(entry[..dash], out var from) ||
                    !TryStrictAddress(entry[(dash + 1)..], out var to) ||
                    from.AddressFamily != to.AddressFamily ||
                    Compare(from, to) > 0)
                {
                    return false;
                }

                family = from.AddressFamily;
                text = string.Create(CultureInfo.InvariantCulture, $"{from}-{to}");
                isLoopback = IsLoopback(from);
                return true;
            }

            if (!TryStrictAddress(entry, out var address))
            {
                return false;
            }

            family = address.AddressFamily;
            text = address.ToString();
            isLoopback = IsLoopback(address);
            return true;
        }

        /// <summary>Like <c>inet_pton</c>: four dotted decimal octets for IPv4 (the BCL accepts "1.2.3").</summary>
        private static bool TryStrictAddress(string text, out IPAddress address)
        {
            address = IPAddress.None;
            if (text.Length == 0 || text.Contains('%', StringComparison.Ordinal))
            {
                return false;
            }

            if (!text.Contains(':', StringComparison.Ordinal))
            {
                var octets = text.Split('.');
                if (octets.Length != 4 ||
                    octets.Any(octet => octet.Length == 0 || octet.Length > 3 ||
                                        !int.TryParse(octet, NumberStyles.None, CultureInfo.InvariantCulture, out var value) ||
                                        value > 255))
                {
                    return false;
                }
            }

            if (!IPAddress.TryParse(text, out var parsed) ||
                parsed.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
            {
                return false;
            }

            address = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
            return true;
        }

        private static IPAddress Mask(IPAddress address, int prefix)
        {
            var bytes = address.GetAddressBytes();
            for (var i = 0; i < bytes.Length; i++)
            {
                var keep = Math.Clamp(prefix - (i * 8), 0, 8);
                bytes[i] = (byte)(bytes[i] & (byte)(0xFF << (8 - keep)));
            }

            return new IPAddress(bytes);
        }

        private static int Compare(IPAddress a, IPAddress b)
        {
            var x = a.GetAddressBytes();
            var y = b.GetAddressBytes();
            for (var i = 0; i < x.Length; i++)
            {
                if (x[i] != y[i])
                {
                    return x[i].CompareTo(y[i]);
                }
            }

            return 0;
        }

        private static bool IsLoopback(IPAddress address) =>
            address.AddressFamily == AddressFamily.InterNetwork
                ? address.GetAddressBytes()[0] == 127
                : address.Equals(IPAddress.IPv6Loopback);
    }
}
