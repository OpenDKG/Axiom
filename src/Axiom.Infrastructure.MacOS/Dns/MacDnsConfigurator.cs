// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Text.Json;
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.MacOS.Interop;

namespace Axiom.Infrastructure.MacOS.Dns;

/// <summary>Saved DNS state of the network services before Privacy Shield redirected them.</summary>
public sealed record MacDnsBackup
{
    public int SchemaVersion { get; init; } = 1;

    public DateTimeOffset SavedUtc { get; init; }

    public IReadOnlyList<MacDnsServiceBackup> Services { get; init; } = [];

    /// <summary>Resolvers in effect before the redirect; the proxy forwards to these.</summary>
    public IReadOnlyList<string> Upstreams { get; init; } = [];
}

public sealed record MacDnsServiceBackup(string Name, IReadOnlyList<string> Servers);

/// <summary>
/// Points every enabled macOS network service at the loopback resolver with
/// <c>networksetup -setdnsservers</c> and restores the saved servers (or <c>Empty</c> = automatic)
/// afterwards. The backup is written before anything changes, so a crash between redirect and
/// restore is repaired by the fail-safe on the next start (same contract as the Windows
/// PrivacyDnsFailSafe). All tool calls go through <see cref="IProcessRunner"/> for testability.
/// </summary>
public sealed class MacDnsConfigurator
{
    public const string LoopbackResolver = "127.0.0.1";

    private const string NetworkSetup = "/usr/sbin/networksetup";

    private const string Scutil = "/usr/sbin/scutil";

    private const string DsCacheUtil = "/usr/bin/dscacheutil";

    private static readonly TimeSpan ToolTimeout = TimeSpan.FromSeconds(15);

    private static readonly JsonSerializerOptions BackupJson = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    private readonly IProcessRunner _runner;

    private readonly string _backupPath;

    private readonly object _gate = new();

    public MacDnsConfigurator(IProcessRunner runner, string backupPath)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        ArgumentException.ThrowIfNullOrWhiteSpace(backupPath);
        _backupPath = backupPath;
    }

    public string BackupPath => _backupPath;

    public IReadOnlyList<NetworkServiceEntry> ListServices()
    {
        var result = _runner.Run(NetworkSetup, ["-listallnetworkservices"], ToolTimeout);
        return result.Succeeded ? NetworkSetupParser.ParseServices(result.StandardOutput) : [];
    }

    public IReadOnlyList<string>? GetDnsServers(string service)
    {
        var result = _runner.Run(NetworkSetup, ["-getdnsservers", service], ToolTimeout);
        return NetworkSetupParser.ParseDnsServers(result.StandardOutput + "\n" + result.StandardError);
    }

    public bool SetDnsServers(string service, IReadOnlyList<string> servers)
    {
        ArgumentNullException.ThrowIfNull(servers);
        var arguments = new List<string> { "-setdnsservers", service };
        if (servers.Count == 0)
        {
            arguments.Add("Empty");
        }
        else
        {
            arguments.AddRange(servers);
        }

        return _runner.Run(NetworkSetup, arguments, ToolTimeout).Succeeded;
    }

    /// <summary>Current non-loopback system resolvers (from <c>scutil --dns</c>).</summary>
    public IReadOnlyList<IPAddress> DiscoverSystemResolvers()
    {
        var result = _runner.Run(Scutil, ["--dns"], ToolTimeout);
        return result.Succeeded
            ? NetworkSetupParser.ParseScutilNameservers(result.StandardOutput)
                .Where(address => !IPAddress.IsLoopback(address))
                .ToArray()
            : [];
    }

    /// <summary>
    /// Upstreams for the proxy: live system resolvers, or the ones saved before the redirect when
    /// the system already points at the loopback resolver.
    /// </summary>
    public IReadOnlyList<IPEndPoint> DiscoverUpstreams()
    {
        var addresses = DiscoverSystemResolvers().ToList();
        if (addresses.Count == 0 && ReadBackup() is { } backup)
        {
            foreach (var text in backup.Upstreams.Concat(backup.Services.SelectMany(service => service.Servers)))
            {
                if (IPAddress.TryParse(text, out var address) && !IPAddress.IsLoopback(address) && !addresses.Contains(address))
                {
                    addresses.Add(address);
                }
            }
        }

        return addresses.Take(4).Select(address => new IPEndPoint(address, 53)).ToArray();
    }

    /// <summary>Saves the current DNS of every enabled service, then points them at 127.0.0.1.</summary>
    public RedirectResult Redirect()
    {
        lock (_gate)
        {
            var services = ListServices().Where(service => service.Enabled).ToList();
            if (services.Count == 0)
            {
                return new RedirectResult(false, [], "No enabled network service was found.");
            }

            var previous = ReadBackup();
            var saved = new List<MacDnsServiceBackup>();
            foreach (var service in services)
            {
                var servers = GetDnsServers(service.Name);
                if (servers is null)
                {
                    continue;
                }

                if (IsLoopbackOnly(servers))
                {
                    // Already redirected (daemon restart): keep the original backup entry.
                    var original = previous?.Services.FirstOrDefault(entry =>
                        string.Equals(entry.Name, service.Name, StringComparison.Ordinal));
                    saved.Add(original ?? new MacDnsServiceBackup(service.Name, []));
                }
                else
                {
                    saved.Add(new MacDnsServiceBackup(service.Name, servers));
                }
            }

            var upstreams = DiscoverSystemResolvers().Select(address => address.ToString()).ToList();
            if (upstreams.Count == 0 && previous is not null)
            {
                upstreams.AddRange(previous.Upstreams);
            }

            WriteBackup(new MacDnsBackup
            {
                SavedUtc = DateTimeOffset.UtcNow,
                Services = saved,
                Upstreams = upstreams,
            });

            var changed = new List<string>();
            var failed = new List<string>();
            foreach (var entry in saved)
            {
                if (SetDnsServers(entry.Name, [LoopbackResolver]))
                {
                    changed.Add(entry.Name);
                }
                else
                {
                    failed.Add(entry.Name);
                }
            }

            FlushCache();
            return new RedirectResult(
                changed.Count > 0,
                changed,
                failed.Count == 0 ? null : $"networksetup could not change DNS of: {string.Join(", ", failed)}.");
        }
    }

    /// <summary>
    /// Fail-safe: every enabled service that still uses only the loopback resolver gets its saved
    /// servers back (automatic DNS when there is no backup entry). Returns true when anything was
    /// changed.
    /// </summary>
    public bool RestoreIfNeeded()
    {
        lock (_gate)
        {
            var backup = ReadBackup();
            var changed = false;
            foreach (var service in ListServices().Where(service => service.Enabled))
            {
                var servers = GetDnsServers(service.Name);
                if (servers is null || !IsLoopbackOnly(servers))
                {
                    continue;
                }

                var saved = backup?.Services.FirstOrDefault(entry =>
                    string.Equals(entry.Name, service.Name, StringComparison.Ordinal));
                var restore = saved?.Servers.Where(server => !IsLoopbackText(server)).ToArray() ?? [];
                changed |= SetDnsServers(service.Name, restore);
            }

            if (changed)
            {
                FlushCache();
            }

            if (backup is not null && !AnyServiceRedirected())
            {
                TryDeleteBackup();
            }

            return changed;
        }
    }

    public MacDnsBackup? ReadBackup()
    {
        try
        {
            return File.Exists(_backupPath)
                ? JsonSerializer.Deserialize<MacDnsBackup>(File.ReadAllText(_backupPath), BackupJson)
                : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    public static bool IsLoopbackOnly(IReadOnlyList<string> servers) =>
        servers.Count > 0 && servers.All(IsLoopbackText);

    private static bool IsLoopbackText(string server) =>
        IPAddress.TryParse(server, out var address) && IPAddress.IsLoopback(address);

    private bool AnyServiceRedirected() =>
        ListServices()
            .Where(service => service.Enabled)
            .Any(service => GetDnsServers(service.Name) is { } servers && IsLoopbackOnly(servers));

    private void WriteBackup(MacDnsBackup backup) =>
        FilterRulesFile.WriteAtomic(_backupPath, JsonSerializer.Serialize(backup, BackupJson) + "\n");

    private void TryDeleteBackup()
    {
        try
        {
            File.Delete(_backupPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Kept; harmless because restore only touches loopback-only services.
        }
    }

    private void FlushCache() => _runner.Run(DsCacheUtil, ["-flushcache"], ToolTimeout);
}

public sealed record RedirectResult(bool Changed, IReadOnlyList<string> Services, string? Error);
