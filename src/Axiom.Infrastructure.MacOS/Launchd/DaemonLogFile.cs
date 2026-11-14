// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;

namespace Axiom.Infrastructure.MacOS.Launchd;

/// <summary>
/// RED skeleton (tests first): the daemon log writer. Rotation handling is not implemented yet.
/// </summary>
public sealed class DaemonLogFile : TextWriter
{
    private readonly StreamWriter _writer;

    private int _reopenCount = -0;

    public DaemonLogFile(string path, TimeSpan checkInterval)
    {
        _ = checkInterval;
        _writer = new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete)) { AutoFlush = true };
    }

    public override Encoding Encoding => _writer.Encoding;

    public int ReopenCount => _reopenCount;

    public static void WritePidFile(string path) => throw new NotImplementedException(path);

    public void Reopen() => throw new NotImplementedException($"{_writer} {_reopenCount}");

    public override void Write(char value) => _writer.Write(value);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _writer.Dispose();
        }

        base.Dispose(disposing);
    }
}
