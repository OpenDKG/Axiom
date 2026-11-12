// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Nft;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

internal sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = start;

    public override DateTimeOffset GetUtcNow() => Now;
}

internal sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "axiom-nft-tests-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
            // Best effort.
        }
    }
}

internal sealed class CollectingSink : IFilterEventSink
{
    public List<string> Lines { get; } = [];

    public void Emit(string ndjsonLine) => Lines.Add(ndjsonLine);
}

/// <summary>Records every nft invocation; `-f -` scripts are kept as the "table", `-j list` answers from a canned JSON.</summary>
internal sealed class FakeNftRunner : INftRunner
{
    public List<(IReadOnlyList<string> Args, string? Stdin)> Calls { get; } = [];

    public string? AppliedScript { get; private set; }

    public long? TableGeneration { get; set; }

    public string? ListJson { get; set; }

    public string? ApplyError { get; set; }

    public Task<NftResult> RunAsync(IReadOnlyList<string> args, string? standardInput, CancellationToken ct)
    {
        Calls.Add((args, standardInput));
        var joined = string.Join(' ', args);
        if (joined == "-f -")
        {
            if (ApplyError is not null)
            {
                return Task.FromResult(new NftResult(1, string.Empty, ApplyError));
            }

            AppliedScript = standardInput;
            var marker = "comment \"axiom generation ";
            var at = standardInput!.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
            TableGeneration = long.Parse(standardInput[at..standardInput.IndexOf('"', at)], CultureInfo.InvariantCulture);
            return Task.FromResult(new NftResult(0, string.Empty, string.Empty));
        }

        if (joined.StartsWith("-j list table inet axiom", StringComparison.Ordinal))
        {
            if (TableGeneration is null)
            {
                return Task.FromResult(new NftResult(1, string.Empty, "Error: No such file or directory"));
            }

            var json = ListJson ??
                       "{\"nftables\":[{\"table\":{\"family\":\"inet\",\"name\":\"axiom\",\"handle\":1,\"comment\":\"axiom generation " +
                       TableGeneration.Value.ToString(CultureInfo.InvariantCulture) + "\"}}]}";
            return Task.FromResult(new NftResult(0, json, string.Empty));
        }

        if (joined == "delete table inet axiom")
        {
            TableGeneration = null;
            AppliedScript = null;
            return Task.FromResult(new NftResult(0, string.Empty, string.Empty));
        }

        return Task.FromResult(new NftResult(0, string.Empty, string.Empty));
    }
}

/// <summary>In-memory cgroup tree + process table.</summary>
internal sealed class FakeCgroupFs : ICgroupFs
{
    public HashSet<string> Cgroups { get; } = new(StringComparer.Ordinal) { "", "user.slice", "system.slice", "init.scope" };

    public Dictionary<int, (string Exe, string Cgroup)> Processes { get; } = [];

    public Dictionary<string, string> AppPaths { get; } = new(StringComparer.Ordinal);

    public HashSet<int> Unmovable { get; } = [];

    public List<(int Pid, string Target)> Moves { get; } = [];

    public bool CreateFails { get; set; }

    public bool CgroupExists(string cgroupPath) => Cgroups.Contains(cgroupPath);

    public void CreateCgroup(string cgroupPath)
    {
        if (CreateFails)
        {
            throw new IOException("Read-only file system");
        }

        var parts = cgroupPath.Split('/');
        for (var i = 1; i <= parts.Length; i++)
        {
            Cgroups.Add(string.Join('/', parts[..i]));
        }
    }

    public bool TryRemoveCgroup(string cgroupPath) =>
        ReadProcs(cgroupPath).Count == 0 && ListChildCgroups(cgroupPath).Count == 0 && Cgroups.Remove(cgroupPath);

    public IReadOnlyList<string> ListChildCgroups(string cgroupPath) =>
        Cgroups.Where(c => c.StartsWith(cgroupPath + "/", StringComparison.Ordinal) && !c[(cgroupPath.Length + 1)..].Contains('/', StringComparison.Ordinal)).ToList();

    public IReadOnlyList<int> ReadProcs(string cgroupPath) =>
        Processes.Where(p => p.Value.Cgroup == cgroupPath).Select(p => p.Key).ToList();

    public void MoveProcess(int pid, string cgroupPath)
    {
        if (!CgroupExists(cgroupPath))
        {
            throw new IOException("No such file or directory");
        }

        if (Unmovable.Contains(pid))
        {
            throw new UnauthorizedAccessException("Permission denied");
        }

        if (!Processes.TryGetValue(pid, out var process))
        {
            throw new IOException("No such process");
        }

        Processes[pid] = (process.Exe, cgroupPath);
        Moves.Add((pid, cgroupPath));
    }

    public IReadOnlyList<int> ListPids() => Processes.Keys.OrderBy(pid => pid).ToList();

    public string? ReadProcessCgroup(int pid) => Processes.TryGetValue(pid, out var p) ? p.Cgroup : null;

    public string? ReadProcessExe(int pid) => Processes.TryGetValue(pid, out var p) ? p.Exe : null;

    public string? ResolveAppPath(string appPath) => AppPaths.TryGetValue(appPath, out var resolved) ? resolved : null;

    public Dictionary<int, int> Parents { get; } = [];

    public int? ReadParentPid(int pid) => Parents.TryGetValue(pid, out var ppid) ? ppid : null;
}

internal static class Specs
{
    public static RuleSpec Block(string appPath, Guid? id = null, FirewallDirection direction = FirewallDirection.Outbound) => new()
    {
        ManagedRuleId = id ?? Guid.NewGuid(),
        AppPath = appPath,
        Direction = direction,
        Action = FirewallAction.Block,
        CreatedBy = "uid:1000",
    };

    public static RuleSpec Allow(string appPath, Guid? id = null) => Block(appPath, id) with { Action = FirewallAction.Allow };
}
