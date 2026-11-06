// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;

namespace Axiom.Infrastructure.Linux.Firewall;

/// <summary>Wire layout shared with <c>axiom_fw.bpf.c</c>. Sizes are asserted before use.</summary>
internal static class FirewallPolicyLayout
{
    public const int ExeKeySize = 16;

    public const int ExeValueSize = 8;

    public const int RuleKeySize = 24;

    public const int RuleValueSize = 32;

    public const int MaxSlots = 16;

    public static byte[] ExeKey(ExecutableIdentity identity) => identity.KeyBytes();

    public static byte[] ExeValue(bool allowOut, bool allowIn, int ruleCount)
    {
        var value = new byte[ExeValueSize];
        value[0] = allowOut ? (byte)1 : (byte)0;
        value[1] = allowIn ? (byte)1 : (byte)0;
        BitConverter.TryWriteBytes(value.AsSpan(4, 4), ruleCount);
        return value;
    }

    public static byte[] RuleKey(ulong hi, ulong lo, int index)
    {
        var key = new byte[RuleKeySize];
        BitConverter.TryWriteBytes(key.AsSpan(0, 8), hi);
        BitConverter.TryWriteBytes(key.AsSpan(8, 8), lo);
        BitConverter.TryWriteBytes(key.AsSpan(16, 4), index);
        return key;
    }

    public static byte[] RuleValue(CompiledSlot slot)
    {
        var value = new byte[RuleValueSize];
        value[0] = slot.Action == FirewallAction.Block ? (byte)0 : (byte)1;
        value[1] = slot.Protocol;
        value[2] = slot.Family;
        value[3] = slot.Prefix;
        BitConverter.TryWriteBytes(value.AsSpan(4, 2), slot.PortMin);
        BitConverter.TryWriteBytes(value.AsSpan(6, 2), slot.PortMax);
        slot.Address.CopyTo(value.AsSpan(8, 16));
        value[24] = slot.Direction;
        value[25] = slot.Enabled ? (byte)1 : (byte)0;
        return value;
    }
}

internal sealed record CompiledSlot(
    Guid ManagedRuleId,
    FirewallAction Action,
    byte Direction,
    byte Protocol,
    byte Family,
    byte Prefix,
    ushort PortMin,
    ushort PortMax,
    byte[] Address,
    bool Enabled);

internal sealed record CompiledExecutable(
    ExecutableIdentity Identity,
    bool AllowOut,
    bool AllowIn,
    IReadOnlyList<CompiledSlot> Slots);

internal sealed record CompileError(string Code, string Message);

internal static class FirewallPolicyCompiler
{
    public static bool TryCompile(
        ExecutableIdentity identity,
        IReadOnlyList<RuleSpec> specs,
        out CompiledExecutable? compiled,
        out CompileError? error)
    {
        compiled = null;
        error = null;

        var slots = new List<CompiledSlot>();
        var allowOut = false;
        var allowIn = false;

        foreach (var spec in specs.OrderBy(spec => spec.ManagedRuleId))
        {
            var validation = RuleSpecValidator.Validate(spec);
            if (!validation.IsValid)
            {
                error = new CompileError(
                    validation.Errors[0].Code,
                    string.Join("; ", validation.Errors.Select(item => $"{item.Code}: {item.Message}")));
                return false;
            }

            if (spec.Profiles != FirewallProfile.All)
            {
                error = new CompileError(
                    "rule.scope.unsupported_platform",
                    "Linux has no Windows network profiles; a rule restricted to a profile cannot be " +
                    "expressed and is refused instead of being broadened to every interface.");
                return false;
            }

            var direction = spec.Direction == FirewallDirection.Outbound ? (byte)1 : (byte)0;

            if (spec.Direction == FirewallDirection.Inbound)
            {
                if (spec.Action == FirewallAction.Allow)
                {
                    error = new CompileError(
                        "rule.scope.unsupported_platform",
                        "Inbound allow rules need the remote peer address, which a bind hook cannot " +
                        "see; the rule is refused instead of being installed with broader effect.");
                    return false;
                }

                if (spec.RemoteAddresses.Count > 0)
                {
                    error = new CompileError(
                        "rule.scope.unsupported_platform",
                        "Inbound remote-address scope cannot be enforced on a bind hook; the rule " +
                        "is refused instead of being broadened.");
                    return false;
                }

                if (!string.IsNullOrWhiteSpace(spec.RemotePorts))
                {
                    // RuleSpec.RemotePorts means the peer port on Windows. A bind hook only sees
                    // the local port, so accepting it would silently change the rule's meaning.
                    error = new CompileError(
                        "rule.scope.unsupported_platform",
                        "Inbound rules cannot be scoped to a remote port: a bind hook sees the local " +
                        "port only. The rule is refused instead of blocking unrelated local ports.");
                    return false;
                }
            }

            if (!TryParsePorts(spec.RemotePorts, out var ports, out var portError))
            {
                error = new CompileError("rule.ports.invalid", portError);
                return false;
            }

            if (spec.Protocol == NetworkProtocol.Any && ports.Count > 1)
            {
                error = new CompileError(
                    "rule.scope.unsupported_platform",
                    "A port list requires a concrete protocol (TCP or UDP).");
                return false;
            }

            if (!TryParseAddresses(spec.RemoteAddresses, out var addresses, out var addressError))
            {
                error = new CompileError("rule.addresses.invalid", addressError);
                return false;
            }

            var combinations = Math.Max(1, addresses.Count) * Math.Max(1, ports.Count);
            if (slots.Count + combinations > FirewallPolicyLayout.MaxSlots)
            {
                error = new CompileError(
                    "rule.expansion_limit",
                    $"This executable needs more than {FirewallPolicyLayout.MaxSlots} kernel rule slots; " +
                    "narrow the address/port lists.");
                return false;
            }

            if (spec.Enabled)
            {
                if (spec.Direction == FirewallDirection.Outbound && spec.Action == FirewallAction.Allow)
                {
                    allowOut = true;
                }

                if (spec.Direction == FirewallDirection.Inbound && spec.Action == FirewallAction.Allow)
                {
                    allowIn = true;
                }
            }

            var addressList = addresses.Count == 0
                ? new List<(byte Family, byte Prefix, byte[] Address)> { (0, 0, new byte[16]) }
                : addresses;
            var portList = ports.Count == 0
                ? new List<(ushort Min, ushort Max)> { (0, 0) }
                : ports;

            foreach (var (family, prefix, address) in addressList)
            {
                foreach (var (min, max) in portList)
                {
                    slots.Add(new CompiledSlot(
                        spec.ManagedRuleId,
                        spec.Action,
                        direction,
                        (byte)spec.Protocol,
                        family,
                        prefix,
                        min,
                        max,
                        address,
                        spec.Enabled));
                }
            }
        }

        compiled = new CompiledExecutable(identity, allowOut, allowIn, slots);
        return true;
    }

    private static bool TryParsePorts(
        string? value,
        out List<(ushort Min, ushort Max)> ports,
        out string error)
    {
        ports = [];
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(value) || value == "*")
        {
            return true;
        }

        foreach (var part in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var bounds = part.Split('-', StringSplitOptions.TrimEntries);
            if (bounds.Length is < 1 or > 2)
            {
                error = $"'{part}' is not a port or port range.";
                return false;
            }

            if (!TryPort(bounds[0], out var min) ||
                (bounds.Length == 2 && !TryPort(bounds[1], out var max)))
            {
                error = $"'{part}' is not a port number between 1 and 65535.";
                return false;
            }

            var upper = bounds.Length == 2 ? bounds[1] : bounds[0];
            if (!TryPort(upper, out var high) || min > high)
            {
                error = $"'{part}' has an invalid range.";
                return false;
            }

            ports.Add((min, high));
        }

        return true;

        static bool TryPort(string text, out ushort value) =>
            ushort.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value) && value > 0;
    }

    private static bool TryParseAddresses(
        IReadOnlyList<string> values,
        out List<(byte Family, byte Prefix, byte[] Address)> addresses,
        out string error)
    {
        addresses = [];
        error = string.Empty;

        foreach (var value in values)
        {
            var parts = value.Split('/', StringSplitOptions.TrimEntries);
            if (parts.Length is < 1 or > 2 || !IPAddress.TryParse(parts[0], out var address))
            {
                error = $"'{value}' is not an IP address or CIDR range.";
                return false;
            }

            var family = address.AddressFamily switch
            {
                AddressFamily.InterNetwork => 4,
                AddressFamily.InterNetworkV6 => 6,
                _ => 0,
            };

            if (family == 0)
            {
                error = $"'{value}' is not an IPv4 or IPv6 address.";
                return false;
            }

            var maxPrefix = family == 4 ? 32 : 128;
            var prefix = maxPrefix;
            if (parts.Length == 2 &&
                (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out prefix) ||
                 prefix is < 0 || prefix > maxPrefix))
            {
                error = $"'{value}' has an invalid prefix length.";
                return false;
            }

            var bytes = new byte[16];
            var raw = address.GetAddressBytes();
            raw.CopyTo(bytes, 0);
            Mask(bytes, prefix);
            addresses.Add(((byte)family, (byte)prefix, bytes));
        }

        return true;
    }

    private static void Mask(byte[] address, int prefix)
    {
        for (var i = 0; i < address.Length; i++)
        {
            var bits = prefix - i * 8;
            if (bits >= 8)
            {
                continue;
            }

            address[i] = bits <= 0 ? (byte)0 : (byte)(address[i] & (0xff << (8 - bits)));
        }
    }
}
