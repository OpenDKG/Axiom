// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Net;
using Axiom.Contracts.Threat;

namespace Axiom.Service.Hosting.Dns;

/// <summary>Process facts an OS adapter supplies to <see cref="ProcessDnsAppAttributor"/>.</summary>
public interface IDnsProcessLookup
{
    /// <summary>Pid owning the local socket <paramref name="source"/>, or 0 when unknown.</summary>
    int FindOwningProcess(IPEndPoint source, bool tcp);

    /// <summary>Display name and executable path of <paramref name="processId"/> (empty when unknown).</summary>
    (string Name, string Path) Describe(int processId);

    /// <summary>Parent pid, or 0 when unknown.</summary>
    int ParentProcessId(int processId);

    /// <summary>Pids at or below this value are kernel/system and are never attributed.</summary>
    int SystemProcessIdLimit { get; }
}

/// <summary>
/// Shared attribution logic: owner lookup, a 30 s per-pid cache and the walk to the nearest AI
/// agent ancestor. Agents usually fetch through a tool process (curl, git, nslookup), so the
/// querying process is not the agent itself; remembering the nearest agent ancestor is what makes
/// "fetched by tool" provable.
/// </summary>
public sealed class ProcessDnsAppAttributor(IDnsProcessLookup lookup) : IDnsAppAttributor
{
    private const int MaxCacheEntries = 256;

    private const int MaxAncestorDepth = 6;

    private static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(30);

    private readonly IDnsProcessLookup _lookup = lookup ?? throw new ArgumentNullException(nameof(lookup));

    private readonly ConcurrentDictionary<int, (DnsAppIdentity Identity, DateTimeOffset ResolvedUtc)> _cache = new();

    public DnsAppIdentity? Resolve(IPEndPoint source, bool tcp)
    {
        ArgumentNullException.ThrowIfNull(source);

        var processId = _lookup.FindOwningProcess(source, tcp);
        if (processId <= _lookup.SystemProcessIdLimit)
        {
            return DnsAppIdentity.Unknown;
        }

        var now = DateTimeOffset.UtcNow;
        if (_cache.TryGetValue(processId, out var cached) && now - cached.ResolvedUtc < CacheLifetime)
        {
            return cached.Identity;
        }

        var (name, path) = _lookup.Describe(processId);
        var (agentName, agentPath) = FindAgentAncestor(processId);
        var identity = new DnsAppIdentity(name, path, agentName, agentPath);

        _cache[processId] = (identity, now);
        if (_cache.Count > MaxCacheEntries)
        {
            foreach (var pair in _cache)
            {
                if (now - pair.Value.ResolvedUtc > CacheLifetime)
                {
                    _cache.TryRemove(pair.Key, out _);
                }
            }
        }

        return identity;
    }

    private (string Name, string Path) FindAgentAncestor(int processId)
    {
        var current = processId;
        for (var depth = 0; depth < MaxAncestorDepth && current > _lookup.SystemProcessIdLimit; depth++)
        {
            var parent = _lookup.ParentProcessId(current);
            if (parent <= _lookup.SystemProcessIdLimit || parent == current)
            {
                return (string.Empty, string.Empty);
            }

            var (name, path) = _lookup.Describe(parent);
            if (name.Length > 0 && AgentProcessMatcher.IsAgentProcess(name, path))
            {
                return (name, path);
            }

            current = parent;
        }

        return (string.Empty, string.Empty);
    }
}
