// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers;
using System.Text;

namespace Axiom.Infrastructure.MacOS.Filter;

/// <summary>
/// Newline-delimited reader for an untrusted stream. Unlike the IPC reader it does not end the
/// connection on an oversized line: the line is dropped (counted in <see cref="DroppedLines"/>) and
/// reading resumes after the next newline, so one bad event cannot cut the filter's stream.
/// </summary>
public sealed class BoundedLineReader(Stream stream, int maxLineBytes)
{
    private readonly Stream _stream = stream ?? throw new ArgumentNullException(nameof(stream));

    private readonly byte[] _buffer = new byte[16 * 1024];

    private readonly ArrayBufferWriter<byte> _line = new(1024);

    private int _offset;

    private int _count;

    private bool _discarding;

    public long DroppedLines { get; private set; }

    /// <summary>Next complete line (without the terminator), or null at end of stream.</summary>
    public async Task<string?> ReadLineAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            if (_offset == _count)
            {
                _count = await _stream.ReadAsync(_buffer, cancellationToken).ConfigureAwait(false);
                _offset = 0;
                if (_count == 0)
                {
                    // A final unterminated line is still delivered unless it was oversized.
                    if (_line.WrittenCount > 0 && !_discarding)
                    {
                        return TakeLine();
                    }

                    return null;
                }
            }

            var span = _buffer.AsSpan(_offset, _count - _offset);
            var newline = span.IndexOf((byte)'\n');
            var chunk = newline >= 0 ? span[..newline] : span;
            _offset += newline >= 0 ? newline + 1 : span.Length;

            if (!_discarding)
            {
                if (_line.WrittenCount + chunk.Length > maxLineBytes)
                {
                    _discarding = true;
                    _line.ResetWrittenCount();
                    DroppedLines++;
                }
                else
                {
                    _line.Write(chunk);
                }
            }

            if (newline >= 0)
            {
                if (_discarding)
                {
                    _discarding = false;
                    continue;
                }

                return TakeLine();
            }
        }
    }

    private string TakeLine()
    {
        var text = Encoding.UTF8.GetString(_line.WrittenSpan).TrimEnd('\r');
        _line.ResetWrittenCount();
        return text;
    }
}
