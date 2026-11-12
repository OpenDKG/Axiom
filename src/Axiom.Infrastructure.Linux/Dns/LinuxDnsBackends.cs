// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Infrastructure.Unix.Filter;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Dns;

public enum LinuxDnsBackend
{
    /// <summary>systemd-resolved: per-link DNS over <c>resolvectl</c>; <c>/etc/resolv.conf</c> is its stub.</summary>
    SystemdResolved = 0,

    /// <summary>NetworkManager without resolved: per-connection <c>ipv4.dns</c>/<c>ipv6.dns</c> via <c>nmcli</c>.</summary>
    NetworkManager = 1,

    /// <summary>Plain <c>/etc/resolv.conf</c> (static file, rewritten with a backup).</summary>
    ResolvConf = 2,
}

/// <summary>One DNS-bearing link/connection as the backend sees it. Empty servers = automatic.</summary>
public sealed record LinuxDnsLink(string Name, string Description, IReadOnlyList<string> Servers, IReadOnlyList<string> Domains);

/// <summary>Minimal surface the configurator and the recovery adapter need from a resolver backend.</summary>
public interface ILinuxDnsBackend
{
    LinuxDnsBackend Kind { get; }

    /// <summary>Links/connections that currently carry resolver configuration (what a redirect must cover).</summary>
    IReadOnlyList<LinuxDnsLink> ListLinks();

    /// <summary>Writes the servers (and routing domains where the backend has them); empty servers = back to automatic.</summary>
    bool SetDns(string link, IReadOnlyList<string> servers, IReadOnlyList<string> domains);

    void FlushCache();
}

/// <summary>Picks the backend of the running host (docs/LINUX_ARCHITECTURE.md §5).</summary>
public static class LinuxDnsBackendDetector
{
    public const string ResolvConfPath = "/etc/resolv.conf";

    public const string ResolvedStubPath = "/run/systemd/resolve/stub-resolv.conf";

    private static readonly TimeSpan ToolTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Pure decision from the facts a doctor or test supplies.</summary>
    public static LinuxDnsBackend Decide(string? resolvConfTarget, bool resolvectlWorks, bool networkManagerRunning)
    {
        var resolvedOwnsResolvConf = resolvConfTarget?.Contains("systemd/resolve", StringComparison.Ordinal) == true;
        if (resolvedOwnsResolvConf && resolvectlWorks)
        {
            return LinuxDnsBackend.SystemdResolved;
        }

        return networkManagerRunning ? LinuxDnsBackend.NetworkManager : LinuxDnsBackend.ResolvConf;
    }

    public static LinuxDnsBackend Detect(IProcessRunner runner)
    {
        ArgumentNullException.ThrowIfNull(runner);
        string? target = null;
        try
        {
            target = new FileInfo(ResolvConfPath).LinkTarget ?? (File.Exists(ResolvedStubPath) && File.Exists(ResolvConfPath) ? null : null);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A missing resolv.conf is handled as a static file.
        }

        var resolvectl = runner.Run(ResolvedDnsBackend.Resolvectl, ["dns"], ToolTimeout);
        var nm = runner.Run(NetworkManagerDnsBackend.Nmcli, ["-t", "-g", "RUNNING", "general"], ToolTimeout);
        return Decide(
            target,
            resolvectl.Succeeded,
            nm.Succeeded && nm.StandardOutput.Trim().Equals("running", StringComparison.OrdinalIgnoreCase));
    }

    public static ILinuxDnsBackend Create(LinuxDnsBackend kind, IProcessRunner runner) => kind switch
    {
        LinuxDnsBackend.SystemdResolved => new ResolvedDnsBackend(runner),
        LinuxDnsBackend.NetworkManager => new NetworkManagerDnsBackend(runner),
        _ => new ResolvConfDnsBackend(ResolvConfPath),
    };
}

/// <summary><c>resolvectl dns</c> / <c>resolvectl domain</c> per link; <c>~.</c> routes every query to the link.</summary>
public sealed class ResolvedDnsBackend : ILinuxDnsBackend
{
    public const string Resolvectl = "/usr/bin/resolvectl";

    public const string RouteAllDomain = "~.";

    private static readonly TimeSpan ToolTimeout = TimeSpan.FromSeconds(15);

    private readonly IProcessRunner _runner;

    public ResolvedDnsBackend(IProcessRunner runner)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
    }

    public LinuxDnsBackend Kind => LinuxDnsBackend.SystemdResolved;

    public IReadOnlyList<LinuxDnsLink> ListLinks()
    {
        var dns = _runner.Run(Resolvectl, ["dns"], ToolTimeout);
        if (!dns.Succeeded)
        {
            return [];
        }

        var domains = _runner.Run(Resolvectl, ["domain"], ToolTimeout);
        var domainMap = domains.Succeeded ? ParseLinks(domains.StandardOutput) : new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        return ParseLinks(dns.StandardOutput)
            .Where(pair => pair.Value.Count > 0)
            .Select(pair => new LinuxDnsLink(pair.Key, "systemd-resolved link", pair.Value, domainMap.GetValueOrDefault(pair.Key, [])))
            .ToList();
    }

    public bool SetDns(string link, IReadOnlyList<string> servers, IReadOnlyList<string> domains)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(link);
        ArgumentNullException.ThrowIfNull(servers);
        ArgumentNullException.ThrowIfNull(domains);
        if (servers.Count == 0)
        {
            return _runner.Run(Resolvectl, ["revert", link], ToolTimeout).Succeeded;
        }

        var ok = _runner.Run(Resolvectl, ["dns", link, .. servers], ToolTimeout).Succeeded;
        if (ok)
        {
            ok = _runner.Run(Resolvectl, ["domain", link, .. domains], ToolTimeout).Succeeded;
        }

        return ok;
    }

    public void FlushCache() => _runner.Run(Resolvectl, ["flush-caches"], ToolTimeout);

    /// <summary>Parses <c>Global: ...</c> / <c>Link 2 (eno2): 192.168.70.1 fe80::1%eno2</c> lines into name → values (Global excluded).</summary>
    public static Dictionary<string, IReadOnlyList<string>> ParseLinks(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var links = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (!line.StartsWith("Link ", StringComparison.Ordinal))
            {
                continue;
            }

            var open = line.IndexOf('(', StringComparison.Ordinal);
            var close = line.IndexOf(')', StringComparison.Ordinal);
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (open < 0 || close < open || colon < close)
            {
                continue;
            }

            var name = line[(open + 1)..close];
            var values = line[(colon + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            links[name] = values;
        }

        return links;
    }
}

/// <summary><c>nmcli</c> per active connection; a redirect pins <c>ipv4.dns 127.0.0.1</c> and ignores the DHCP servers.</summary>
public sealed class NetworkManagerDnsBackend : ILinuxDnsBackend
{
    public const string Nmcli = "/usr/bin/nmcli";

    private static readonly TimeSpan ToolTimeout = TimeSpan.FromSeconds(20);

    private static readonly string[] IgnoredTypes = ["loopback", "bridge", "tun", "veth", "dummy", "wireguard"];

    private readonly IProcessRunner _runner;

    public NetworkManagerDnsBackend(IProcessRunner runner)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
    }

    public LinuxDnsBackend Kind => LinuxDnsBackend.NetworkManager;

    public IReadOnlyList<LinuxDnsLink> ListLinks()
    {
        var active = _runner.Run(Nmcli, ["-t", "-f", "NAME,UUID,DEVICE,TYPE", "connection", "show", "--active"], ToolTimeout);
        if (!active.Succeeded)
        {
            return [];
        }

        var links = new List<LinuxDnsLink>();
        foreach (var (name, uuid, device, type) in ParseActiveConnections(active.StandardOutput))
        {
            if (IgnoredTypes.Contains(type, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            var settings = _runner.Run(Nmcli, ["-t", "-g", "ipv4.dns,ipv4.ignore-auto-dns,ipv6.dns,ipv6.ignore-auto-dns", "connection", "show", uuid], ToolTimeout);
            var servers = settings.Succeeded ? ParseDnsSettings(settings.StandardOutput) : [];
            links.Add(new LinuxDnsLink(uuid, $"{name} ({device}, {type})", servers, []));
        }

        return links;
    }

    public bool SetDns(string link, IReadOnlyList<string> servers, IReadOnlyList<string> domains)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(link);
        ArgumentNullException.ThrowIfNull(servers);
        var ipv4 = servers.Where(server => IPAddress.TryParse(server, out var address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToList();
        var ipv6 = servers.Where(server => IPAddress.TryParse(server, out var address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6).ToList();
        var ignore = servers.Count > 0 ? "yes" : "no";
        var modify = _runner.Run(
            Nmcli,
            [
                "connection", "modify", link,
                "ipv4.dns", string.Join(',', ipv4), "ipv4.ignore-auto-dns", ignore,
                "ipv6.dns", string.Join(',', ipv6), "ipv6.ignore-auto-dns", ignore,
            ],
            ToolTimeout);
        if (!modify.Succeeded)
        {
            return false;
        }

        var device = _runner.Run(Nmcli, ["-t", "-g", "GENERAL.DEVICES", "connection", "show", link], ToolTimeout);
        var deviceName = device.StandardOutput.Trim();
        return deviceName.Length == 0 || _runner.Run(Nmcli, ["device", "reapply", deviceName], ToolTimeout).Succeeded;
    }

    public void FlushCache()
    {
        // NetworkManager has no resolver cache of its own; glibc does not cache.
    }

    public static IReadOnlyList<(string Name, string Uuid, string Device, string Type)> ParseActiveConnections(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var connections = new List<(string, string, string, string)>();
        foreach (var raw in output.Split('\n'))
        {
            var parts = raw.Trim().Split(':');
            if (parts.Length >= 4 && parts[1].Length > 0)
            {
                connections.Add((parts[0], parts[1], parts[2], parts[3]));
            }
        }

        return connections;
    }

    /// <summary>Four <c>-g</c> lines: ipv4.dns, ipv4.ignore-auto-dns, ipv6.dns, ipv6.ignore-auto-dns → explicit servers.</summary>
    public static IReadOnlyList<string> ParseDnsSettings(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var lines = output.Split('\n');
        var servers = new List<string>();
        foreach (var index in new[] { 0, 2 })
        {
            if (lines.Length > index)
            {
                servers.AddRange(lines[index].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            }
        }

        return servers;
    }
}

/// <summary>Static <c>/etc/resolv.conf</c>: one pseudo-link whose servers are its <c>nameserver</c> lines.</summary>
public sealed class ResolvConfDnsBackend : ILinuxDnsBackend
{
    public const string LinkName = "resolv.conf";

    public const string RedirectHeader = "# Written by axiomd (Axiom Privacy Shield); the previous file is restored when the shield stops.";

    private readonly string _path;

    public ResolvConfDnsBackend(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = path;
    }

    public LinuxDnsBackend Kind => LinuxDnsBackend.ResolvConf;

    public string Path => _path;

    public IReadOnlyList<LinuxDnsLink> ListLinks()
    {
        var text = ReadText();
        return text is null ? [] : [new LinuxDnsLink(LinkName, _path, ParseNameservers(text), ParseSearch(text))];
    }

    public bool SetDns(string link, IReadOnlyList<string> servers, IReadOnlyList<string> domains)
    {
        ArgumentNullException.ThrowIfNull(servers);
        ArgumentNullException.ThrowIfNull(domains);
        try
        {
            FilterRulesFile.WriteAtomic(_path, Render(servers, domains), FilterRulesFile.PublishedMode);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Writes an exact earlier file back (restore path).</summary>
    public bool WriteRaw(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        try
        {
            FilterRulesFile.WriteAtomic(_path, text, FilterRulesFile.PublishedMode);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public string? ReadText()
    {
        try
        {
            return File.Exists(_path) ? File.ReadAllText(_path) : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public void FlushCache()
    {
    }

    public static string Render(IReadOnlyList<string> servers, IReadOnlyList<string> domains)
    {
        var lines = new List<string> { RedirectHeader };
        lines.AddRange(servers.Select(server => "nameserver " + server));
        if (domains.Count > 0)
        {
            lines.Add("search " + string.Join(' ', domains));
        }

        lines.Add("options edns0 trust-ad");
        return string.Join('\n', lines) + "\n";
    }

    public static IReadOnlyList<string> ParseNameservers(string text) => Parse(text, "nameserver");

    public static IReadOnlyList<string> ParseSearch(string text) => Parse(text, "search");

    private static List<string> Parse(string text, string keyword)
    {
        ArgumentNullException.ThrowIfNull(text);
        var values = new List<string>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith('#') || line.StartsWith(';'))
            {
                continue;
            }

            var parts = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 && string.Equals(parts[0], keyword, StringComparison.Ordinal))
            {
                values.AddRange(parts.Skip(1));
            }
        }

        return values;
    }
}
