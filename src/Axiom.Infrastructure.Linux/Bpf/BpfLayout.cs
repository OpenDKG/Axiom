// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers.Binary;
using System.Globalization;

namespace Axiom.Infrastructure.Linux.Bpf;

/// <summary>
/// Byte-exact mirror of <c>Bpf/native/axiom_bpf.h</c> (ABI <see cref="Abi"/>): map names, verdict
/// values and the packed key/value encodings handed to <c>bpftool map update … key hex … value hex …</c>.
/// Everything is little-endian because the BPF program reads the structs natively on x86/arm64.
/// </summary>
public static class BpfLayout
{
    public const int Abi = 1;

    public const string ExeMap = "axiom_exe_verdicts";
    public const string CgroupMap = "axiom_cgroup_verdicts";
    public const string EventsMap = "axiom_events";
    public const string StatsMap = "axiom_stats";
    public const string SelfCheckMap = "axiom_selfcheck";
    public const int SelfCheckSize = 40;

    public static byte[] SelfCheckRequest(int tgid) => new byte[SelfCheckSize];

    public static BpfSelfCheckRecord? ParseSelfCheck(string? hex) => null;

    public const byte ActionAllow = 1;
    public const byte ActionBlock = 2;

    public const byte ProtoTcp = 1;
    public const byte ProtoUdp = 2;
    public const byte ProtoOther = 4;
    public const byte ProtoAny = ProtoTcp | ProtoUdp | ProtoOther;

    public const int ExeKeySize = 16;
    public const int CgroupKeySize = 8;
    public const int VerdictSize = 24;

    /// <summary>Program (function) names in the object; bpftool pins each under the pin directory by this name.</summary>
    public static readonly IReadOnlyList<(string Hook, string Program)> Programs =
    [
        ("connect4", "axiom_connect4"),
        ("connect6", "axiom_connect6"),
        ("sendmsg4", "axiom_sendmsg4"),
        ("sendmsg6", "axiom_sendmsg6"),
    ];

    public static byte[] ExeKey(uint devMajor, uint devMinor, ulong ino, ulong subvolume = 0)
    {
        var bytes = new byte[ExeKeySize];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0, 4), devMajor);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4, 4), devMinor);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(8, 8), ino);
        return bytes;
    }

    public static byte[] CgroupKey(ulong cgroupId)
    {
        var bytes = new byte[CgroupKeySize];
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, cgroupId);
        return bytes;
    }

    /// <summary>struct axiom_verdict: action, proto mask, reserved, generation (u32), rule id (Guid byte order).</summary>
    public static byte[] Verdict(byte action, byte protoMask, long generation, Guid ruleId)
    {
        var bytes = new byte[VerdictSize];
        bytes[0] = action;
        bytes[1] = protoMask;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4, 4), unchecked((uint)generation));
        ruleId.TryWriteBytes(bytes.AsSpan(8, 16));
        return bytes;
    }

    /// <summary>The <c>hex</c> token list bpftool expects: one two-digit lowercase byte per argument.</summary>
    public static IReadOnlyList<string> HexTokens(ReadOnlySpan<byte> bytes)
    {
        var tokens = new string[bytes.Length];
        for (var i = 0; i < bytes.Length; i++)
        {
            tokens[i] = bytes[i].ToString("x2", CultureInfo.InvariantCulture);
        }

        return tokens;
    }

    /// <summary>Stable text form of a key (for logs and the in-memory applied set).</summary>
    public static string HexString(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);

    /// <summary>Parses the 32-hex-char rule id printed by the event helper back into the Guid.</summary>
    public static Guid? ParseRuleId(string? hex)
    {
        if (hex is null || hex.Length != 32)
        {
            return null;
        }

        try
        {
            var bytes = Convert.FromHexString(hex);
            var guid = new Guid(bytes);
            return guid == Guid.Empty ? null : guid;
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
