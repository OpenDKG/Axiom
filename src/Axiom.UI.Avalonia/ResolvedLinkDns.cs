// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Net;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Per-link DNS servers on a systemd-resolved host. <see cref="System.Net.NetworkInformation"/>
/// reads <c>/etc/resolv.conf</c>, which in stub mode names only <c>127.0.0.53</c>; the servers the
/// Axiom daemon switches live in resolved itself (<c>resolvectl dns</c>:
/// <c>Link 2 (eno2): 192.168.70.1</c>). Without this the Privacy Shield page would take the stub
/// for its own 127.0.0.1 resolver and raise a false "DNS is not answering" alert.
/// </summary>
public static class ResolvedLinkDns
{
    public const string ResolvectlPath = "/usr/bin/resolvectl";

    /// <summary>The resolved stub listeners; never a Privacy Shield resolver address.</summary>
    public static bool IsStub(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return address.Equals(IPAddress.Parse("127.0.0.53")) || address.Equals(IPAddress.Parse("127.0.0.54"));
    }

    /// <summary>Parses <c>resolvectl dns</c> output into link name → servers (links without DNS map to an empty list).</summary>
    public static IReadOnlyDictionary<string, IReadOnlyList<IPAddress>> Parse(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var links = new Dictionary<string, IReadOnlyList<IPAddress>>(StringComparer.Ordinal);
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
            var servers = line[(colon + 1)..]
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(token => token.Split('%', 2)[0].Split('#', 2)[0])
                .Select(token => IPAddress.TryParse(token, out var address) ? address : null)
                .Where(address => address is not null)
                .Select(address => address!)
                .ToArray();
            links[name] = servers;
        }

        return links;
    }

    /// <summary>Live read; null when resolvectl is missing or fails (callers fall back to resolv.conf minus the stub).</summary>
    public static IReadOnlyDictionary<string, IReadOnlyList<IPAddress>>? Read()
    {
        if (!OperatingSystem.IsLinux() || !File.Exists(ResolvectlPath))
        {
            return null;
        }

        try
        {
            var startInfo = new ProcessStartInfo(ResolvectlPath)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            startInfo.ArgumentList.Add("dns");
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return null;
            }

            var output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(3000))
            {
                process.Kill();
                return null;
            }

            return process.ExitCode == 0 ? Parse(output) : null;
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return null;
        }
    }
}
