// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace Axiom.Infrastructure.MacOS.Launchd;

/// <summary>
/// The daemon's own log file (<c>/Library/Logs/Axiom/axiomd.log</c>, 0600). launchd opens
/// <c>StandardOutPath</c> once per spawn and keeps that descriptor, so after newsyslog renames the
/// log every later line went into the rotated archive (and, once compressed, into an unlinked file).
/// axiomd therefore writes its log through this writer, which follows the path:
/// <list type="bullet">
/// <item><see cref="Reopen"/> on SIGHUP, which newsyslog sends through <see cref="LaunchdServiceInstaller.PidFilePath"/>;</item>
/// <item>a rotation check before a write (at most every <c>checkInterval</c>): the path is gone,
/// or the file at the path is not the one held (its size differs from the held file's size).</item>
/// </list>
/// A file it creates is 0600; a file newsyslog created is set to 0600 on reopen
/// (<see cref="MacLogPermissions"/>). With <c>redirectStandardStreams</c> the new descriptor is also
/// duplicated onto fd 1 and 2, so native output (runtime crash text) lands in the current file too.
/// Logging never throws into the caller.
/// </summary>
public sealed class DaemonLogFile : TextWriter
{
    private const int StandardOutput = 1;

    private const int StandardError = 2;

    private readonly Lock _gate = new();

    private readonly string _path;

    private readonly long _checkIntervalMs;

    private readonly bool _redirectStandardStreams;

    private readonly bool _announceReopen;

    private FileStream? _stream;

    private StreamWriter? _writer;

    private long _lastCheck;

    private int _reopenCount;

    /// <param name="announceReopen">Write one line naming the reason at the top of each reopened file.</param>
    public DaemonLogFile(string path, TimeSpan checkInterval, bool redirectStandardStreams = false, bool announceReopen = false)
        : base(CultureInfo.InvariantCulture)
    {
        _announceReopen = announceReopen;
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = path;
        _checkIntervalMs = (long)Math.Max(0, checkInterval.TotalMilliseconds);
        _redirectStandardStreams = redirectStandardStreams && !OperatingSystem.IsWindows();
        lock (_gate)
        {
            OpenCore();
        }
    }

    public override Encoding Encoding { get; } = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    public string Path => _path;

    /// <summary>How many times the writer moved to a new file (SIGHUP or detected rotation).</summary>
    public int ReopenCount => Volatile.Read(ref _reopenCount);

    /// <summary>
    /// Writes this process id to <paramref name="path"/> (0644, the usual pid file mode; it only
    /// names a process) for newsyslog's signal column.
    /// </summary>
    public static void WritePidFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var temp = path + ".tmp";
        File.WriteAllText(temp, Environment.ProcessId.ToString(CultureInfo.InvariantCulture) + "\n");
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(temp, UnixDataDirectoryPermissions.SharedFileMode);
        }

        File.Move(temp, path, overwrite: true);
    }

    /// <summary>Closes the held file and opens the file now at <see cref="Path"/> (SIGHUP).</summary>
    public void Reopen()
    {
        lock (_gate)
        {
            ReopenCore("signal");
        }
    }

    public override void Write(char value) => Append(writer => writer.Write(value));

    public override void Write(string? value) => Append(writer => writer.Write(value));

    public override void Write(char[] buffer, int index, int count) => Append(writer => writer.Write(buffer, index, count));

    public override void WriteLine() => Append(writer => writer.WriteLine());

    public override void WriteLine(string? value) => Append(writer => writer.WriteLine(value));

    public override void Flush()
    {
        lock (_gate)
        {
            TryFlush();
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            lock (_gate)
            {
                CloseCore();
            }
        }

        base.Dispose(disposing);
    }

    private void Append(Action<StreamWriter> write)
    {
        lock (_gate)
        {
            try
            {
                CheckRotation();
                if (_writer is not null)
                {
                    write(_writer);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ObjectDisposedException)
            {
                // A log line is never worth failing the daemon for; the next write retries the open.
                CloseCore();
            }
        }
    }

    private void CheckRotation()
    {
        if (_stream is null)
        {
            OpenCore();
            return;
        }

        var now = Environment.TickCount64;
        if (_checkIntervalMs > 0 && now - _lastCheck < _checkIntervalMs)
        {
            return;
        }

        _lastCheck = now;
        TryFlush();
        if (IsRotated())
        {
            ReopenCore("rotation detected");
        }
    }

    /// <summary>
    /// True when <see cref="Path"/> no longer names the held file: it is missing, or its size
    /// differs from the held file's size (same inode means same size; the held descriptor is
    /// queried with fstat, the path with stat).
    /// </summary>
    private bool IsRotated()
    {
        try
        {
            var atPath = new FileInfo(_path);
            if (!atPath.Exists)
            {
                return true;
            }

            return atPath.Length != RandomAccess.GetLength(_stream!.SafeFileHandle);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ObjectDisposedException)
        {
            return true;
        }
    }

    private void ReopenCore(string reason)
    {
        CloseCore();
        OpenCore();
        if (_stream is null)
        {
            return;
        }

        _reopenCount++;
        if (_announceReopen)
        {
            _writer!.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"{DateTimeOffset.UtcNow:yyyy-MM-ddTHH:mm:ss.fffZ} axiomd[{Environment.ProcessId}]: log reopened ({reason}), reopen #{_reopenCount}"));
        }
    }

    private void OpenCore()
    {
        try
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.Append,
                Access = FileAccess.Write,
                // Shared write/delete: the length is never cached and newsyslog may rename it.
                Share = FileShare.ReadWrite | FileShare.Delete,
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = MacLogPermissions.FileMode;
            }

            var stream = new FileStream(_path, options);
            if (!OperatingSystem.IsWindows() && File.GetUnixFileMode(_path) != MacLogPermissions.FileMode)
            {
                File.SetUnixFileMode(_path, MacLogPermissions.FileMode);
            }

            _stream = stream;
            _writer = new StreamWriter(stream, Encoding) { AutoFlush = true };
            _lastCheck = Environment.TickCount64;
            if (_redirectStandardStreams)
            {
                var fd = (int)stream.SafeFileHandle.DangerousGetHandle();
                _ = Dup2(fd, StandardOutput);
                _ = Dup2(fd, StandardError);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _stream = null;
            _writer = null;
        }
    }

    private void CloseCore()
    {
        try
        {
            _writer?.Dispose();
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException)
        {
        }

        _writer = null;
        _stream = null;
    }

    private void TryFlush()
    {
        try
        {
            _writer?.Flush();
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException)
        {
        }
    }

    [DllImport("libc", EntryPoint = "dup2", SetLastError = true)]
    private static extern int Dup2(int oldFd, int newFd);
}
