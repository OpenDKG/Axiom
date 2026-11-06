// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;

namespace Axiom.Infrastructure.Linux.ProcFs;

/// <summary>Process attribution read from <c>/proc/&lt;pid&gt;</c>.</summary>
public sealed record ProcProcessIdentity(
    int ProcessId,
    string DisplayName,
    string ExecutablePath,
    long StartTimeTicks,
    bool IsResolved);

/// <summary>
/// Resolves a PID to an executable path and a start time. The start time is part of the identity
/// key so a recycled PID is never merged with the previous process's first-seen row.
/// </summary>
public sealed class ProcProcessIdentityResolver(string procRoot = "/proc")
{
    private const string UnknownName = "Unknown process";

    private readonly string _procRoot = procRoot;

    public ProcProcessIdentity Resolve(int processId)
    {
        if (processId <= 0)
        {
            return new ProcProcessIdentity(processId, "Kernel or unknown socket", string.Empty, 0, false);
        }

        var directory = Path.Combine(_procRoot, processId.ToString(CultureInfo.InvariantCulture));
        var command = ReadTrimmed(Path.Combine(directory, "comm"));
        var executable = ReadExecutable(directory);
        var startTime = ReadStartTime(Path.Combine(directory, "stat"));

        if (command.Length == 0 && executable.Length == 0 && startTime == 0)
        {
            return new ProcProcessIdentity(processId, UnknownName, string.Empty, 0, false);
        }

        var displayName = command.Length > 0 ? command : Path.GetFileName(executable);
        return new ProcProcessIdentity(
            processId,
            displayName.Length > 0 ? displayName : UnknownName,
            executable,
            startTime,
            executable.Length > 0);
    }

    private static string ReadExecutable(string directory)
    {
        var target = ProcLinkReader.Read(Path.Combine(directory, "exe"));
        if (string.IsNullOrWhiteSpace(target))
        {
            return string.Empty;
        }

        // A replaced or deleted binary keeps running; the kernel appends this marker.
        const string DeletedSuffix = " (deleted)";
        return target.EndsWith(DeletedSuffix, StringComparison.Ordinal)
            ? target[..^DeletedSuffix.Length]
            : target;
    }

    private static string ReadTrimmed(string path)
    {
        try
        {
            return File.Exists(path) ? File.ReadAllText(path).Trim() : string.Empty;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return string.Empty;
        }
    }

    internal static long ReadStartTime(string statPath)
    {
        try
        {
            if (!File.Exists(statPath))
            {
                return 0;
            }

            var stat = File.ReadAllText(statPath);
            var close = stat.LastIndexOf(')');
            if (close < 0 || close + 2 >= stat.Length)
            {
                return 0;
            }

            // Fields after the command: state=3 ... starttime=22, so index 19 of the tail.
            var fields = stat[(close + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return fields.Length > 19 &&
                   long.TryParse(fields[19], NumberStyles.None, CultureInfo.InvariantCulture, out var value)
                ? value
                : 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }
}
