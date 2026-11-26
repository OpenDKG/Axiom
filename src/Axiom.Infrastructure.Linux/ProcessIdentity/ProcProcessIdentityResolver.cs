// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Globalization;
using Axiom.Contracts.Monitoring;

namespace Axiom.Infrastructure.Linux.ProcessIdentity;

/// <summary>What the daemon knows about a Linux process from <c>/proc/&lt;pid&gt;</c>.</summary>
public sealed record LinuxProcessIdentity
{
    public required int ProcessId { get; init; }

    /// <summary>Resolved <c>exe</c> link (empty when unreadable); a deleted binary keeps its path without the suffix.</summary>
    public required string Path { get; init; }

    public required string DisplayName { get; init; }

    public string CommandLine { get; init; } = string.Empty;

    public int? ParentProcessId { get; init; }

    public string ParentProcessName { get; init; } = string.Empty;

    /// <summary>Ancestors nearest first: <c>bash(1200) > gnome-terminal(900) > systemd(1)</c>.</summary>
    public string ParentChain { get; init; } = string.Empty;

    public uint? Uid { get; init; }
}

public interface ILinuxProcessIdentitySource
{
    LinuxProcessIdentity Resolve(int processId, string? knownPath);
}

/// <summary>
/// Identity from <c>/proc/&lt;pid&gt;/exe</c> (path), <c>cmdline</c>, <c>comm</c> and
/// <c>stat</c> (ppid) with a short cache. Linux has no code-signing identity, so signer fields
/// stay "Unavailable" in the shared model; package ownership is a later phase.
/// </summary>
public sealed class ProcProcessIdentityResolver : ILinuxProcessIdentitySource
{
    private const int MaxChainDepth = 6;

    private static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(10);

    private static readonly TimeSpan HomeCacheLifetime = TimeSpan.FromMinutes(5);

    private readonly string _procRoot;

    private readonly TimeProvider _time;

    private readonly string _passwdPath;

    private readonly TimeSpan? _sanitiserTimeout;

    private volatile Tuple<IReadOnlyDictionary<string, string>, DateTimeOffset>? _homes;

    private readonly ConcurrentDictionary<int, (LinuxProcessIdentity Identity, DateTimeOffset ResolvedUtc)> _cache = new();

    public ProcProcessIdentityResolver()
        : this("/proc", TimeProvider.System)
    {
    }

    /// <param name="sanitiserTimeout">
    /// Match timeout for the command-line sanitiser; its default when null.
    /// </param>
    public ProcProcessIdentityResolver(
        string procRoot, TimeProvider time, string passwdPath = "/etc/passwd", TimeSpan? sanitiserTimeout = null)
    {
        _sanitiserTimeout = sanitiserTimeout;
        ArgumentException.ThrowIfNullOrWhiteSpace(passwdPath);
        _passwdPath = passwdPath;
        ArgumentException.ThrowIfNullOrWhiteSpace(procRoot);
        _procRoot = procRoot;
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    public LinuxProcessIdentity Resolve(int processId, string? knownPath)
    {
        var now = _time.GetUtcNow();
        if (_cache.TryGetValue(processId, out var cached) && now - cached.ResolvedUtc < CacheLifetime)
        {
            return cached.Identity;
        }

        if (_cache.Count > 4096)
        {
            _cache.Clear();
        }

        var identity = Read(processId, knownPath);
        _cache[processId] = (identity, now);
        return identity;
    }

    private LinuxProcessIdentity Read(int processId, string? knownPath)
    {
        var directory = System.IO.Path.Combine(_procRoot, processId.ToString(CultureInfo.InvariantCulture));
        var path = ReadExe(directory);
        if (path.Length == 0 && !string.IsNullOrEmpty(knownPath))
        {
            path = knownPath;
        }

        var comm = ReadText(System.IO.Path.Combine(directory, "comm")).Trim();
        var (parent, _) = ReadStat(directory);
        var uid = ReadUid(directory);
        var written = JoinArguments(ReadText(System.IO.Path.Combine(directory, "cmdline")));
        var home = uid is { } owner ? ReadHomeDirectory(owner) : null;
        var commandLine = _sanitiserTimeout is { } timeout
            ? CommandLineSanitizer.Sanitize(written, home, timeout)
            : CommandLineSanitizer.Sanitize(written, home);

        var chain = new List<string>();
        var parentName = string.Empty;
        var ancestor = parent;
        for (var depth = 0; depth < MaxChainDepth && ancestor is > 0; depth++)
        {
            var ancestorDirectory = System.IO.Path.Combine(_procRoot, ancestor.Value.ToString(CultureInfo.InvariantCulture));
            var ancestorComm = ReadText(System.IO.Path.Combine(ancestorDirectory, "comm")).Trim();
            if (depth == 0)
            {
                parentName = ancestorComm;
            }

            chain.Add(string.Create(CultureInfo.InvariantCulture, $"{(ancestorComm.Length > 0 ? ancestorComm : "?")}({ancestor.Value})"));
            if (ancestor == 1)
            {
                break;
            }

            (ancestor, _) = ReadStat(ancestorDirectory);
        }

        return new LinuxProcessIdentity
        {
            ProcessId = processId,
            Path = path,
            DisplayName = path.Length > 0 ? System.IO.Path.GetFileName(path) : comm,
            CommandLine = commandLine,
            ParentProcessId = parent,
            ParentProcessName = parentName,
            ParentChain = string.Join(" > ", chain),
            Uid = uid,
        };
    }

    /// <summary>Resolves <c>exe</c>; the kernel appends <c>" (deleted)"</c> after an upgrade in place.</summary>
    public static string ReadExe(string processDirectory)
    {
        try
        {
            var target = new FileInfo(System.IO.Path.Combine(processDirectory, "exe")).LinkTarget ?? string.Empty;
            const string deleted = " (deleted)";
            return target.EndsWith(deleted, StringComparison.Ordinal) ? target[..^deleted.Length] : target;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return string.Empty;
        }
    }

    /// <summary>Parses <c>/proc/&lt;pid&gt;/stat</c>: ppid is the field after the parenthesised comm (which may contain spaces).</summary>
    public static (int? ParentProcessId, char State) ParseStat(string stat)
    {
        ArgumentNullException.ThrowIfNull(stat);
        var end = stat.LastIndexOf(')');
        if (end < 0)
        {
            return (null, '?');
        }

        var rest = stat[(end + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (rest.Length < 2 || !int.TryParse(rest[1], NumberStyles.None, CultureInfo.InvariantCulture, out var ppid))
        {
            return (null, '?');
        }

        return (ppid, rest[0].Length > 0 ? rest[0][0] : '?');
    }

    private static (int? ParentProcessId, char State) ReadStat(string processDirectory) =>
        ParseStat(ReadText(System.IO.Path.Combine(processDirectory, "stat")));

    /// <summary>
    /// Joins the NUL-separated <c>cmdline</c> arguments. An argument with spaces is quoted (only its
    /// value for <c>name=value</c>), so the sanitiser still sees where it ends.
    /// </summary>
    private static string JoinArguments(string cmdline) =>
        string.Join(' ', cmdline.TrimEnd('\0').Split('\0').Select(QuoteArgument));

    private static string QuoteArgument(string argument)
    {
        if (!argument.Any(char.IsWhiteSpace))
        {
            return argument;
        }

        var equals = argument.IndexOf('=', StringComparison.Ordinal);
        var split = equals > 0 && !argument.AsSpan(0, equals).ContainsAny(' ', '\t') ? equals + 1 : 0;
        return argument[..split] + "\"" + argument[split..].Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
    }

    /// <summary>Home directory from a uid map of the passwd file, re-read every few minutes.</summary>
    private string? ReadHomeDirectory(uint uid)
    {
        var now = _time.GetUtcNow();
        var cached = _homes;
        if (cached is null || now - cached.Item2 >= HomeCacheLifetime)
        {
            var homes = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var line in ReadText(_passwdPath).Split('\n'))
            {
                var fields = line.Split(':');
                if (fields.Length >= 6)
                {
                    homes.TryAdd(fields[2], fields[5]);
                }
            }

            _homes = cached = Tuple.Create<IReadOnlyDictionary<string, string>, DateTimeOffset>(homes, now);
        }

        return cached.Item1.GetValueOrDefault(uid.ToString(CultureInfo.InvariantCulture));
    }

    private static uint? ReadUid(string processDirectory)
    {
        foreach (var line in ReadText(System.IO.Path.Combine(processDirectory, "status")).Split('\n'))
        {
            if (line.StartsWith("Uid:", StringComparison.Ordinal))
            {
                var parts = line[4..].Split('\t', StringSplitOptions.RemoveEmptyEntries);
                return parts.Length > 0 && uint.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var uid) ? uid : null;
            }
        }

        return null;
    }

    private static string ReadText(string path)
    {
        try
        {
            return File.Exists(path) ? File.ReadAllText(path) : string.Empty;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return string.Empty;
        }
    }
}
