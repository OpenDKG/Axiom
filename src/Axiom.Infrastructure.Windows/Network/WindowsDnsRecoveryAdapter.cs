// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security;
using Axiom.Contracts.NetworkRecovery;
using Microsoft.Win32;

namespace Axiom.Infrastructure.Windows.Network;

/// <summary>
/// Reads and restores per-adapter DNS through the documented Windows cmdlets. Static versus
/// automatic is decided from the interface's persisted <c>NameServer</c> override, so a captured
/// "automatic" entry is restored by clearing the override instead of inventing DHCP servers.
/// </summary>
public sealed class WindowsDnsRecoveryAdapter : INetworkRecoveryDnsAdapter
{
    private const string TcpipInterfaces = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

    private const string Tcpip6Interfaces = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";

    private const int CommandTimeoutMilliseconds = 15_000;

    public IReadOnlyList<NetworkAdapterDnsState> CaptureDns()
    {
        var adapters = new List<NetworkAdapterDnsState>();

        IEnumerable<NetworkInterface> networks;
        try
        {
            networks = NetworkInterface.GetAllNetworkInterfaces();
        }
        catch (NetworkInformationException exception)
        {
            throw new NetworkRecoveryPlatformException(
                "dns_capture_failed",
                $"Network adapters could not be enumerated: {exception.Message}",
                exception);
        }

        foreach (var network in networks)
        {
            if (network.OperationalStatus != OperationalStatus.Up ||
                network.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                !Guid.TryParse(network.Id, out var adapterId) ||
                adapterId == Guid.Empty)
            {
                continue;
            }

            var state = CaptureAdapter(network, adapterId);
            if (state is not null)
            {
                adapters.Add(state);
            }
        }

        return adapters;
    }

    public void ApplyDns(NetworkAdapterDnsState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        if (state.AdapterId == Guid.Empty)
        {
            throw new NetworkRecoveryPlatformException(
                "dns_adapter_invalid",
                "The saved adapter identifier is empty.");
        }

        if (string.IsNullOrWhiteSpace(state.InterfaceAlias))
        {
            throw new NetworkRecoveryPlatformException(
                "dns_adapter_invalid",
                "The saved adapter alias is empty.");
        }

        ValidateFamily(state.Ipv4Mode, state.Ipv4Servers, AddressFamily.InterNetwork, "IPv4");
        ValidateFamily(state.Ipv6Mode, state.Ipv6Servers, AddressFamily.InterNetworkV6, "IPv6");

        var alias = ResolveAlias(state.AdapterId, state.InterfaceAlias);
        var current = CaptureOne(state.AdapterId);
        var applyIpv4 = current is null || !FamilyMatches(
            current.Ipv4Mode,
            current.Ipv4Servers,
            state.Ipv4Mode,
            state.Ipv4Servers);
        var applyIpv6 = current is null || !FamilyMatches(
            current.Ipv6Mode,
            current.Ipv6Servers,
            state.Ipv6Mode,
            state.Ipv6Servers);

        if (!applyIpv4 && !applyIpv6)
        {
            return;
        }

        if (applyIpv4)
        {
            ApplyFamily(alias, ipv6: false, state.Ipv4Mode, state.Ipv4Servers);
        }

        if (applyIpv6)
        {
            ApplyFamily(alias, ipv6: true, state.Ipv6Mode, state.Ipv6Servers);
        }

        FlushDnsCache();

        var after = CaptureOne(state.AdapterId)
            ?? throw new NetworkRecoveryPlatformException(
                "dns_verify_missing",
                $"Adapter '{state.InterfaceAlias}' is no longer present after the DNS restore.");

        if (!FamilyMatches(after.Ipv4Mode, after.Ipv4Servers, state.Ipv4Mode, state.Ipv4Servers) ||
            !FamilyMatches(after.Ipv6Mode, after.Ipv6Servers, state.Ipv6Mode, state.Ipv6Servers))
        {
            throw new NetworkRecoveryPlatformException(
                "dns_verify_failed",
                $"Adapter '{state.InterfaceAlias}' did not read back with the saved DNS configuration.");
        }
    }

    public void FlushDnsCache()
    {
        try
        {
            using var process = Process.Start(CreateFlushDnsStart());

            process?.WaitForExit(5_000);
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            // Cache flushing is an optimisation; the adapter read-back is the real verification.
        }
    }

    public bool AnyAdapterUsesLoopbackDns()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(adapter => adapter.OperationalStatus == OperationalStatus.Up &&
                                  adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Any(adapter => adapter.GetIPProperties().DnsAddresses.Any(IPAddress.IsLoopback));
        }
        catch (NetworkInformationException)
        {
            return false;
        }
    }

    private static NetworkAdapterDnsState? CaptureAdapter(NetworkInterface network, Guid adapterId)
    {
        IPInterfaceProperties properties;
        try
        {
            properties = network.GetIPProperties();
        }
        catch (NetworkInformationException exception)
        {
            throw new NetworkRecoveryPlatformException(
                "dns_capture_failed",
                $"DNS properties for adapter '{network.Name}' could not be read: {exception.Message}",
                exception);
        }

        var ipv4 = DistinctAddresses(properties.DnsAddresses, AddressFamily.InterNetwork);
        var ipv6 = DistinctAddresses(properties.DnsAddresses, AddressFamily.InterNetworkV6);

        var ipv4Override = ReadStaticServers(adapterId, ipv6: false);
        var ipv6Override = ReadStaticServers(adapterId, ipv6: true);
        var ipv4Mode = ipv4Override.HasOverride ? NetworkDnsMode.Static : NetworkDnsMode.Automatic;
        var ipv6Mode = ipv6Override.HasOverride ? NetworkDnsMode.Static : NetworkDnsMode.Automatic;

        if (ipv4Mode == NetworkDnsMode.Automatic &&
            ipv6Mode == NetworkDnsMode.Automatic &&
            ipv4.Count == 0 &&
            ipv6.Count == 0)
        {
            // Nothing was configured for this adapter, so there is nothing recovery can restore.
            return null;
        }

        if (ipv4Mode == NetworkDnsMode.Static && ipv4Override.Servers.Count == 0)
        {
            throw new NetworkRecoveryPlatformException(
                "dns_capture_incomplete",
                $"Adapter '{network.Name}' has a static IPv4 override that could not be read.");
        }

        if (ipv6Mode == NetworkDnsMode.Static && ipv6Override.Servers.Count == 0)
        {
            throw new NetworkRecoveryPlatformException(
                "dns_capture_incomplete",
                $"Adapter '{network.Name}' has a static IPv6 override that could not be read.");
        }

        return new NetworkAdapterDnsState
        {
            AdapterId = adapterId,
            InterfaceAlias = network.Name,
            Description = network.Description,
            Ipv4Mode = ipv4Mode,
            Ipv6Mode = ipv6Mode,
            // Effective servers are what Windows uses; the persisted override is the fallback when
            // the adapter has no live DNS right now.
            Ipv4Servers = ipv4Mode == NetworkDnsMode.Static
                ? (ipv4.Count > 0 ? ipv4 : ipv4Override.Servers)
                : [],
            Ipv6Servers = ipv6Mode == NetworkDnsMode.Static
                ? (ipv6.Count > 0 ? ipv6 : ipv6Override.Servers)
                : [],
        };
    }

    private static NetworkAdapterDnsState? CaptureOne(Guid adapterId)
    {
        foreach (var network in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!string.Equals(network.Id, adapterId.ToString("D"), StringComparison.OrdinalIgnoreCase) ||
                network.OperationalStatus != OperationalStatus.Up ||
                network.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            return CaptureAdapter(network, adapterId);
        }

        return null;
    }

    /// <summary>Uses the current alias when the adapter was renamed after capture.</summary>
    private static string ResolveAlias(Guid adapterId, string fallback)
    {
        try
        {
            var network = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(candidate =>
                    string.Equals(candidate.Id, adapterId.ToString("D"), StringComparison.OrdinalIgnoreCase));
            return string.IsNullOrWhiteSpace(network?.Name) ? fallback : network.Name;
        }
        catch (NetworkInformationException)
        {
            return fallback;
        }
    }

    private static void ApplyFamily(
        string interfaceAlias,
        bool ipv6,
        NetworkDnsMode mode,
        IReadOnlyList<string> servers)
    {
        var family = ipv6 ? "IPv6" : "IPv4";
        var alias = Escape(interfaceAlias);

        // Set-DnsClientServerAddress has no address-family parameter, but it accepts the exact
        // per-family CIM instances returned by Get-DnsClientServerAddress. This keeps an IPv4
        // restore from rewriting IPv6 (and the other way round).
        var target = $"$target = @(Get-DnsClientServerAddress -InterfaceAlias '{alias}' " +
                     $"-AddressFamily {family} -ErrorAction Stop); " +
                     "if ($target.Count -eq 0) { throw 'the adapter was not found' }; ";

        var command = mode == NetworkDnsMode.Automatic
            ? target + "Set-DnsClientServerAddress -InputObject $target " +
              "-ResetServerAddresses -ErrorAction Stop"
            : target + "Set-DnsClientServerAddress -InputObject $target -ServerAddresses " +
              string.Join(',', servers.Select(server => "'" + Escape(server) + "'")) +
              " -ErrorAction Stop";

        Run(command, $"DNS for {family} could not be restored");
    }

    private static void ValidateFamily(
        NetworkDnsMode mode,
        IReadOnlyList<string> servers,
        AddressFamily family,
        string label)
    {
        if (!Enum.IsDefined(mode))
        {
            throw new NetworkRecoveryPlatformException(
                "dns_mode_invalid",
                $"The saved {label} DNS mode is invalid.");
        }

        if (mode == NetworkDnsMode.Automatic && servers.Count != 0)
        {
            throw new NetworkRecoveryPlatformException(
                "dns_mode_invalid",
                $"The saved {label} DNS mode is automatic but contains static servers.");
        }

        if (mode == NetworkDnsMode.Static && servers.Count == 0)
        {
            throw new NetworkRecoveryPlatformException(
                "dns_mode_invalid",
                $"The saved {label} DNS mode is static but contains no servers.");
        }

        foreach (var server in servers)
        {
            if (!IPAddress.TryParse(server, out var address) || address.AddressFamily != family)
            {
                throw new NetworkRecoveryPlatformException(
                    "dns_server_invalid",
                    $"The saved {label} DNS server '{server}' is not a valid {label} address.");
            }
        }
    }

    private static bool FamilyMatches(
        NetworkDnsMode actualMode,
        IReadOnlyList<string> actualServers,
        NetworkDnsMode expectedMode,
        IReadOnlyList<string> expectedServers)
    {
        if (actualMode != expectedMode)
        {
            return false;
        }

        if (expectedMode == NetworkDnsMode.Automatic)
        {
            return true;
        }

        return SameServers(actualServers, expectedServers);
    }

    private static bool SameServers(IReadOnlyList<string> left, IReadOnlyList<string> right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }

        return left.Select(NormalizeAddress)
            .SequenceEqual(right.Select(NormalizeAddress), StringComparer.OrdinalIgnoreCase);
    }

    private static string NormalizeAddress(string value) =>
        IPAddress.TryParse(value, out var address) ? address.ToString() : value.Trim();

    private static List<string> DistinctAddresses(
        IEnumerable<IPAddress> addresses,
        AddressFamily family)
    {
        var parsed = new List<string>();
        foreach (var address in addresses)
        {
            if (address.AddressFamily != family ||
                address.Equals(IPAddress.Any) ||
                address.Equals(IPAddress.IPv6Any))
            {
                continue;
            }

            var text = address.ToString();
            if (!parsed.Contains(text, StringComparer.OrdinalIgnoreCase))
            {
                parsed.Add(text);
            }
        }

        return parsed;
    }

    /// <summary>
    /// A non-empty <c>NameServer</c> value is Windows' persisted static override. An empty or
    /// missing value means the servers come from DHCP, so restore clears the family instead.
    /// </summary>
    private static StaticServers ReadStaticServers(Guid adapterId, bool ipv6)
    {
        var path = $"{(ipv6 ? Tcpip6Interfaces : TcpipInterfaces)}\\{{{adapterId:D}}}";

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path, writable: false);
            if (key?.GetValue("NameServer") is not string value || string.IsNullOrWhiteSpace(value))
            {
                return new StaticServers(false, []);
            }

            var family = ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            var servers = new List<string>();
            foreach (var part in value.Split(
                         [',', ';', ' '],
                         StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (IPAddress.TryParse(part, out var address) && address.AddressFamily == family)
                {
                    var text = address.ToString();
                    if (!servers.Contains(text, StringComparer.OrdinalIgnoreCase))
                    {
                        servers.Add(text);
                    }
                }
            }

            return new StaticServers(true, servers);
        }
        catch (Exception exception) when (exception is SecurityException or UnauthorizedAccessException or IOException)
        {
            throw new NetworkRecoveryPlatformException(
                "dns_mode_unavailable",
                "The Windows DNS mode could not be read, so no recovery snapshot was taken.",
                exception);
        }
    }

    private readonly record struct StaticServers(bool HasOverride, IReadOnlyList<string> Servers);

    internal static ProcessStartInfo CreateFlushDnsStart() =>
        new(WindowsSystemExecutables.System32("ipconfig.exe"), "/flushdns")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

    internal static ProcessStartInfo CreatePowerShellStart(string command)
    {
        var start = new ProcessStartInfo
        {
            FileName = WindowsSystemExecutables.PowerShell,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-Command");
        start.ArgumentList.Add(command);
        return start;
    }

    private static string Run(string command, string failureMessage)
    {
        var start = CreatePowerShellStart(command);

        try
        {
            using var process = Process.Start(start);
            if (process is null)
            {
                throw new NetworkRecoveryPlatformException(
                    "dns_command_unavailable",
                    $"{failureMessage}: PowerShell could not be started.");
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();

            if (!process.WaitForExit(CommandTimeoutMilliseconds))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                }

                throw new NetworkRecoveryPlatformException(
                    "dns_command_timeout",
                    $"{failureMessage}: the network command timed out.");
            }

            Task.WaitAll(stdoutTask, stderrTask);
            var stdout = stdoutTask.GetAwaiter().GetResult();
            var stderr = stderrTask.GetAwaiter().GetResult();

            if (process.ExitCode != 0)
            {
                var detail = string.IsNullOrWhiteSpace(stderr)
                    ? $"exit code {process.ExitCode}"
                    : stderr.Trim();
                throw new NetworkRecoveryPlatformException(
                    "dns_command_failed",
                    $"{failureMessage}: {detail}");
            }

            return stdout;
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            throw new NetworkRecoveryPlatformException(
                "dns_command_failed",
                $"{failureMessage}: {exception.Message}",
                exception);
        }
    }

    private static string Escape(string value) => value.Replace("'", "''", StringComparison.Ordinal);
}
