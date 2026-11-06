// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers.Binary;
using System.Text;

namespace Netpetra.Infrastructure.Windows.Dns;

internal sealed record DnsQueryInfo(string Domain, int QuestionEnd);

internal static class DnsProtocol
{
    public const int HeaderLength = 12;

    public const int MaxQueryBytes = 4096;

    public static bool TryParseQuery(ReadOnlySpan<byte> buffer, out DnsQueryInfo? query)
    {
        query = null;
        if (buffer.Length < HeaderLength)
        {
            return false;
        }

        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(buffer[4..6]);
        if (questionCount != 1)
        {
            return false;
        }

        var offset = HeaderLength;
        var labels = new List<string>(4);
        var totalLength = 0;

        while (true)
        {
            if (offset >= buffer.Length)
            {
                return false;
            }

            var labelLength = buffer[offset++];
            if (labelLength == 0)
            {
                break;
            }

            if ((labelLength & 0xC0) != 0 || labelLength > 63 || offset + labelLength > buffer.Length)
            {
                return false;
            }

            totalLength += labelLength + 1;
            if (totalLength > 253)
            {
                return false;
            }

            var label = Encoding.ASCII.GetString(buffer.Slice(offset, labelLength));
            if (label.Any(character => character is < (char)33 or > (char)126))
            {
                return false;
            }

            labels.Add(label);
            offset += labelLength;
        }

        if (labels.Count == 0 || offset + 4 > buffer.Length)
        {
            return false;
        }

        query = new DnsQueryInfo(
            string.Join('.', labels).ToLowerInvariant(),
            offset + 4);
        return true;
    }

    public static byte[] BuildResponse(ReadOnlySpan<byte> query, int questionEnd, byte responseCode)
    {
        var length = Math.Clamp(questionEnd, HeaderLength, query.Length);
        var response = new byte[length];
        query[..length].CopyTo(response);

        var flags = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2, 2));
        // Keep RD, set QR and RA, clear the reserved bits and replace the response code.
        flags = (ushort)((flags & 0x0100) | 0x8080 | (responseCode & 0x0F));
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), flags);

        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(8, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10, 2), 0);
        return response;
    }

    public static byte[] BuildError(ReadOnlySpan<byte> query, byte responseCode)
    {
        if (query.Length < HeaderLength)
        {
            return [];
        }

        var response = new byte[HeaderLength];
        query[..HeaderLength].CopyTo(response);

        var flags = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2, 2));
        flags = (ushort)((flags & 0x0100) | 0x8080 | (responseCode & 0x0F));
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(4, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(8, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10, 2), 0);
        return response;
    }

    public static ushort ReadId(ReadOnlySpan<byte> query) =>
        BinaryPrimitives.ReadUInt16BigEndian(query[..2]);
}
