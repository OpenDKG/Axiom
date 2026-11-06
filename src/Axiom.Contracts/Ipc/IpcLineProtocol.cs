// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers;
using System.Text;

namespace Axiom.Contracts.Ipc;

/// <summary>
/// Buffered NDJSON line reader with a hard byte cap. One instance per connection preserves
/// leftover bytes between lines; the static helper is for single-line clients.
/// </summary>
public sealed class IpcLineReader(Stream stream)
{
    private const byte Terminator = (byte)'\n';

    private readonly byte[] _buffer = new byte[16 * 1024];

    private int _offset;

    private int _count;

    public async Task<string?> ReadLineAsync(int maxBytes, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBytes);

        var output = new ArrayBufferWriter<byte>(1024);

        while (true)
        {
            if (_offset == _count)
            {
                _count = await stream.ReadAsync(_buffer, cancellationToken).ConfigureAwait(false);
                _offset = 0;

                if (_count == 0)
                {
                    return output.WrittenCount == 0
                        ? null
                        : Decode(output.WrittenSpan);
                }
            }

            var span = _buffer.AsSpan(_offset, _count - _offset);
            var newline = span.IndexOf(Terminator);

            if (newline >= 0)
            {
                Append(output, span[..newline], maxBytes);
                _offset += newline + 1;
                return Decode(output.WrittenSpan);
            }

            Append(output, span, maxBytes);
            _offset = _count;
        }
    }

    private static void Append(ArrayBufferWriter<byte> output, ReadOnlySpan<byte> bytes, int maxBytes)
    {
        if (output.WrittenCount + bytes.Length > maxBytes)
        {
            throw new IpcMessageTooLargeException(maxBytes);
        }

        output.Write(bytes);
    }

    private static string Decode(ReadOnlySpan<byte> bytes)
    {
        var length = bytes.Length;
        if (length > 0 && bytes[length - 1] == (byte)'\r')
        {
            length--;
        }

        return Encoding.UTF8.GetString(bytes[..length]);
    }
}

public static class IpcLineProtocol
{
    public const byte Terminator = (byte)'\n';

    /// <summary>Reads a single line; use <see cref="IpcLineReader"/> when several lines follow.</summary>
    public static Task<string?> ReadLineAsync(
        Stream stream,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        return new IpcLineReader(stream).ReadLineAsync(maxBytes, cancellationToken);
    }

    public static async Task WriteLineAsync(
        Stream stream,
        string line,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(line);

        var bytes = Encoding.UTF8.GetBytes(line + "\n");
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}

public sealed class IpcMessageTooLargeException(int maxBytes)
    : Exception($"IPC message exceeded the {maxBytes} byte limit.");
