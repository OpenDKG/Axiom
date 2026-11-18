// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiom.Infrastructure.Unix.Filter;

namespace Axiom.Infrastructure.Linux.Dns;

/// <summary>Saved resolver state before Privacy Shield redirected the host (<c>privacy-shield-dns-backup.json</c>, 0600).</summary>
public sealed record LinuxDnsBackup
{
    public int SchemaVersion { get; init; } = 1;

    public DateTimeOffset SavedUtc { get; init; }

    public LinuxDnsBackend Backend { get; init; }

    public IReadOnlyList<LinuxDnsLinkBackup> Links { get; init; } = [];

    /// <summary>Resolvers in effect before the redirect; the proxy forwards to these.</summary>
    public IReadOnlyList<string> Upstreams { get; init; } = [];
}

/// <summary><paramref name="RawText"/> is the exact earlier file for the resolv.conf backend.</summary>
public sealed record LinuxDnsLinkBackup(string Name, IReadOnlyList<string> Servers, IReadOnlyList<string> Domains, string? RawText = null);

/// <summary>
/// Points the host's resolver at the loopback proxy and puts it back afterwards (same contract as
/// the macOS <c>MacDnsConfigurator</c> and the Windows PrivacyDnsFailSafe): the backup is written
/// before anything changes; a crash between redirect and restore is repaired on the next start.
/// </summary>
public sealed class LinuxDnsConfigurator
{
    public const string LoopbackResolver = "127.0.0.1";

    private static readonly JsonSerializerOptions BackupJson = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly ILinuxDnsBackend _backend;

    private readonly string _backupPath;

    private readonly object _gate = new();

    public LinuxDnsConfigurator(ILinuxDnsBackend backend, string backupPath)
    {
        _backend = backend ?? throw new ArgumentNullException(nameof(backend));
        ArgumentException.ThrowIfNullOrWhiteSpace(backupPath);
        _backupPath = backupPath;
    }

    public ILinuxDnsBackend Backend => _backend;

    public string BackupPath => _backupPath;

    /// <summary>
    /// Why the last <see cref="RestoreIfNeeded"/> could not put one or more links back, or null.
    /// The backup file is kept while any link still points at loopback, so the next start retries.
    /// </summary>
    public string? LastRestoreError { get; private set; }

    /// <summary>Current non-loopback resolvers across the links.</summary>
    public IReadOnlyList<IPAddress> DiscoverSystemResolvers() =>
        _backend.ListLinks()
            .SelectMany(link => link.Servers)
            .Select(Parse)
            .OfType<IPAddress>()
            .Where(address => !IPAddress.IsLoopback(address))
            .Distinct()
            .ToList();

    /// <summary>Upstreams for the proxy: live resolvers, or the saved ones when the host is already redirected.</summary>
    public IReadOnlyList<IPEndPoint> DiscoverUpstreams()
    {
        var addresses = DiscoverSystemResolvers().ToList();
        if (addresses.Count == 0 && ReadBackup() is { } backup)
        {
            foreach (var text in backup.Upstreams.Concat(backup.Links.SelectMany(link => link.Servers)))
            {
                if (Parse(text) is { } address && !IPAddress.IsLoopback(address) && !addresses.Contains(address))
                {
                    addresses.Add(address);
                }
            }
        }

        return addresses.Take(4).Select(address => new IPEndPoint(address, 53)).ToArray();
    }

    /// <summary>Saves every link's resolver state, then points each one at 127.0.0.1 (routing domain <c>~.</c> on resolved).</summary>
    public LinuxRedirectResult Redirect()
    {
        lock (_gate)
        {
            var links = _backend.ListLinks();
            Log($"redirect ({_backend.Kind}): links={string.Join(", ", links.Select(link => link.Name))}");
            if (links.Count == 0)
            {
                return new LinuxRedirectResult(false, [], "No link with resolver configuration was found.");
            }

            var previous = ReadBackup();
            var saved = new List<LinuxDnsLinkBackup>();
            foreach (var link in links)
            {
                if (IsLoopbackOnly(link.Servers))
                {
                    var original = previous?.Links.FirstOrDefault(entry => string.Equals(entry.Name, link.Name, StringComparison.Ordinal));
                    saved.Add(original ?? new LinuxDnsLinkBackup(link.Name, [], link.Domains));
                }
                else
                {
                    var raw = _backend is ResolvConfDnsBackend file ? file.ReadText() : null;
                    saved.Add(new LinuxDnsLinkBackup(link.Name, link.Servers, link.Domains, raw));
                }
            }

            var upstreams = DiscoverSystemResolvers().Select(address => address.ToString()).ToList();
            if (upstreams.Count == 0 && previous is not null)
            {
                upstreams.AddRange(previous.Upstreams);
            }

            WriteBackup(new LinuxDnsBackup
            {
                SavedUtc = DateTimeOffset.UtcNow,
                Backend = _backend.Kind,
                Links = saved,
                Upstreams = upstreams,
            });

            var changed = new List<string>();
            var failed = new List<string>();
            foreach (var entry in saved)
            {
                var domains = _backend.Kind == LinuxDnsBackend.SystemdResolved ? [ResolvedDnsBackend.RouteAllDomain] : entry.Domains;
                if (_backend.SetDns(entry.Name, [LoopbackResolver], domains))
                {
                    changed.Add(entry.Name);
                }
                else
                {
                    failed.Add(entry.Name);
                }
            }

            _backend.FlushCache();
            return new LinuxRedirectResult(
                changed.Count > 0,
                changed,
                failed.Count == 0 ? null : $"The resolver of these links could not be changed: {string.Join(", ", failed)}.");
        }
    }

    /// <summary>Fail-safe: every link that still points only at loopback gets its saved state back. True when anything changed.</summary>
    public bool RestoreIfNeeded()
    {
        lock (_gate)
        {
            LastRestoreError = null;
            var backup = ReadBackup();
            var changed = false;
            var failed = new List<string>();
            var links = _backend.ListLinks();
            var names = links.Select(link => link.Name).Concat(backup?.Links.Select(link => link.Name) ?? []).Distinct(StringComparer.Ordinal);
            foreach (var name in names)
            {
                var current = links.FirstOrDefault(link => string.Equals(link.Name, name, StringComparison.Ordinal));
                var saved = backup?.Links.FirstOrDefault(entry => string.Equals(entry.Name, name, StringComparison.Ordinal));
                if (current is null || !IsLoopbackOnly(current.Servers))
                {
                    continue;
                }

                bool ok;
                if (saved?.RawText is { } raw && _backend is ResolvConfDnsBackend file)
                {
                    ok = file.WriteRaw(raw);
                }
                else
                {
                    var restore = saved?.Servers.Where(server => !IsLoopbackText(server)).ToArray() ?? [];
                    ok = _backend.SetDns(name, restore, saved?.Domains ?? []);
                }

                Log($"restore '{name}' -> {(saved is null || saved.Servers.Count == 0 ? "automatic" : string.Join(' ', saved.Servers))}: {(ok ? "ok" : "failed")}");
                changed |= ok;
                if (!ok)
                {
                    failed.Add(name);
                }
            }

            if (changed)
            {
                _backend.FlushCache();
            }

            var stillRedirected = _backend.ListLinks().Any(link => IsLoopbackOnly(link.Servers));
            if (backup is not null && !stillRedirected)
            {
                TryDeleteBackup();
            }

            if (failed.Count > 0)
            {
                LastRestoreError =
                    $"The saved DNS could not be restored for: {string.Join(", ", failed)}. " +
                    "The backup was kept and the restore is retried on the next start.";
            }

            return changed;
        }
    }

    public LinuxDnsBackup? ReadBackup()
    {
        try
        {
            return File.Exists(_backupPath)
                ? JsonSerializer.Deserialize<LinuxDnsBackup>(File.ReadAllText(_backupPath), BackupJson)
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
        Parse(server) is { } address && IPAddress.IsLoopback(address);

    /// <summary>resolvectl prints link-local servers as <c>fe80::1%eno2</c>; the scope id is not part of the address.</summary>
    private static IPAddress? Parse(string server)
    {
        var percent = server.IndexOf('%', StringComparison.Ordinal);
        var text = percent > 0 ? server[..percent] : server;
        return IPAddress.TryParse(text, out var address) ? address : null;
    }

    private void WriteBackup(LinuxDnsBackup backup) =>
        FilterRulesFile.WriteAtomic(_backupPath, JsonSerializer.Serialize(backup, BackupJson) + "\n", FilterRulesFile.PrivateMode);

    private void TryDeleteBackup()
    {
        try
        {
            File.Delete(_backupPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Kept; harmless because restore only touches loopback-only links.
        }
    }

    // stderr reaches the journal (systemd) or the terminal; DNS changes must be traceable there.
    private static void Log(string message) => Console.Error.WriteLine("Privacy Shield DNS: " + message);
}

public sealed record LinuxRedirectResult(bool Changed, IReadOnlyList<string> Links, string? Error);
