// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Axiom.Contracts.Ai;
using Axiom.Contracts.Monitoring;

namespace Axiom.UI.Services;

/// <summary>
/// Best-effort local context for the AI evidence package: parent process, signer, product and
/// observed duration. It reads only metadata that the Windows process table and image files expose;
/// it does not read file contents, packet payloads or credential stores. The command line comes with
/// the connection from the platform monitor and is passed through <see cref="CommandLineSanitizer"/>
/// again here.
/// </summary>
public static class AiEvidenceContext
{
    private static readonly ConcurrentDictionary<string, CachedProcessInfo> ProcessCache = new(StringComparer.Ordinal);
    private static readonly object ParentSnapshotGate = new();
    private static readonly TimeSpan ProcessCacheLifetime = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan ParentSnapshotLifetime = TimeSpan.FromSeconds(2);

    private static IReadOnlyDictionary<int, ProcessNode> _parentSnapshot =
        new Dictionary<int, ProcessNode>();
    private static DateTimeOffset _parentSnapshotUtc = DateTimeOffset.MinValue;

    public static AiEvidenceConnection Enrich(AiEvidenceConnection connection, LiveConnection source, DateTimeOffset capturedUtc)
    {
        var info = ResolveProcess(source.ProcessId, source.AppPath);
        var signatureStatus = string.IsNullOrWhiteSpace(source.SignatureStatus)
            ? info.IsSigned switch
            {
                true => "Valid",
                false => "Unsigned",
                _ => "Unavailable",
            }
            : source.SignatureStatus;
        return connection with
        {
            ParentProcessId = source.ParentProcessId ?? info.ParentProcessId,
            ParentProcessName = FirstNonEmpty(source.ParentProcessName, info.ParentProcessName),
            ParentChain = FirstNonEmpty(source.ParentChain, info.ParentChain),
            SignerName = FirstNonEmpty(source.SignerName, info.SignerName),
            SignatureStatus = signatureStatus,
            CommandLine = CommandLineSanitizer.Sanitize(
                source.CommandLine, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)),
            HostedServices = source.HostedServices,
            ParentHostedServices = source.ParentHostedServices,
            Ownership = source.ProcessId == 0
                ? "unowned TIME_WAIT row; Windows does not retain the owner"
                : string.IsNullOrWhiteSpace(source.AppPath)
                    ? "process path unavailable; the process may be protected or already exited"
                    : "resolved",
            ProductName = FirstNonEmpty(source.ProductName, info.ProductName),
            FileVersion = FirstNonEmpty(source.FileVersion, info.FileVersion),
            IsSigned = signatureStatus is "Valid" or "Untrusted",
            ObservedDurationSeconds = Math.Max(
                0,
                (int)(capturedUtc - source.FirstObservedUtc).TotalSeconds),
            RemotePortService = DescribeRemotePort(connection.RemoteEndpoint),
            RuleStatus = source.RuleStatus.ToString(),
        };
    }

    private static string FirstNonEmpty(string primary, string fallback) =>
        !string.IsNullOrWhiteSpace(primary) ? primary : fallback;

    public static AiEvidenceHostContext CollectHost()
    {
        var addresses = new List<string>();
        var prefixes = new List<string>();
        var gateways = new List<string>();
        var dnsSuffix = string.Empty;

        try
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (adapter.OperationalStatus != OperationalStatus.Up ||
                    adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    continue;
                }

                var properties = adapter.GetIPProperties();
                if (string.IsNullOrWhiteSpace(dnsSuffix) &&
                    !string.IsNullOrWhiteSpace(properties.DnsSuffix))
                {
                    dnsSuffix = properties.DnsSuffix;
                }

                foreach (var unicast in properties.UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily is not
                        (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
                    {
                        continue;
                    }

                    if (IPAddress.IsLoopback(unicast.Address) || unicast.Address.IsIPv6LinkLocal)
                    {
                        continue;
                    }

                    addresses.Add(unicast.Address.ToString());
                    if (unicast.PrefixLength > 0)
                    {
                        prefixes.Add($"{unicast.Address}/{unicast.PrefixLength}");
                    }
                }

                foreach (var gateway in properties.GatewayAddresses)
                {
                    if (gateway.Address.Equals(IPAddress.Any) ||
                        gateway.Address.Equals(IPAddress.IPv6Any))
                    {
                        continue;
                    }

                    gateways.Add(gateway.Address.ToString());
                }
            }
        }
        catch (Exception exception) when (exception is
                     NetworkInformationException or PlatformNotSupportedException or
                     InvalidOperationException or SocketException)
        {
            // Host context is optional; the evidence package remains valid without it.
        }

        return new AiEvidenceHostContext(
            addresses.Distinct(StringComparer.Ordinal).Take(16).ToArray(),
            prefixes.Distinct(StringComparer.Ordinal).Take(16).ToArray(),
            gateways.Distinct(StringComparer.Ordinal).Take(8).ToArray(),
            dnsSuffix,
            "Private addresses belong to the local host or its LAN. Axiom does not probe LAN hosts " +
            "or infer their role.");
    }

    public static IReadOnlyList<string> KnownLimitations() =>
    [
        "SNI, TLS certificate subjects, DNS query names and exact per-connection byte counts require " +
        "ETW or packet capture; this build does not collect them.",
        "TIME_WAIT rows have no owner PID in the Windows TCP owner table by design.",
        "No reputation or threat-intelligence feed is configured; no score is inferred.",
        "LAN host identity (the owner or role of a private address) is not probed.",
        "Command lines are best-effort, sanitised and truncated; protected processes may not expose them.",
        "Authenticode trust is evaluated against the local trust store; revocation may not be checked.",
        "Firewall rule status covers only rules created by Axiom, not Windows default policy or " +
        "third-party rules.",
    ];

    public static string DescribeRemotePort(string remoteEndpoint)
    {
        if (string.IsNullOrWhiteSpace(remoteEndpoint))
        {
            return string.Empty;
        }

        var separator = remoteEndpoint.LastIndexOf(':');
        if (separator < 0 || !int.TryParse(remoteEndpoint[(separator + 1)..], out var port))
        {
            return string.Empty;
        }

        return port switch
        {
            20 or 21 => "ftp",
            22 => "ssh",
            23 => "telnet",
            25 => "smtp",
            53 => "dns",
            67 or 68 => "dhcp",
            80 => "http",
            110 => "pop3",
            123 => "ntp",
            135 => "rpc",
            137 or 138 or 139 => "netbios",
            143 => "imap",
            161 or 162 => "snmp",
            389 => "ldap",
            443 => "https",
            445 => "smb",
            465 => "smtps",
            587 => "submission",
            636 => "ldaps",
            993 => "imaps",
            995 => "pop3s",
            1433 => "mssql",
            1521 => "oracle",
            3306 => "mysql",
            3389 => "rdp",
            5432 => "postgresql",
            5672 => "amqp",
            6379 => "redis",
            7680 => "Windows Delivery Optimization (DoSvc)",
            8080 => "http-alt",
            8443 => "https-alt",
            27017 => "mongodb",
            _ => string.Empty,
        };
    }

    private static ProcessMetadata ResolveProcess(int processId, string path)
    {
        var key = $"{processId}|{path}";
        var now = DateTimeOffset.UtcNow;
        if (ProcessCache.TryGetValue(key, out var cached) &&
            now - cached.ResolvedUtc < ProcessCacheLifetime)
        {
            return cached.Metadata;
        }

        var metadata = QueryProcess(processId, path);
        ProcessCache[key] = new CachedProcessInfo(metadata, now);

        if (ProcessCache.Count > 512)
        {
            foreach (var pair in ProcessCache)
            {
                if (now - pair.Value.ResolvedUtc > ProcessCacheLifetime)
                {
                    ProcessCache.TryRemove(pair.Key, out _);
                }
            }
        }

        return metadata;
    }

    private static ProcessMetadata QueryProcess(int processId, string path)
    {
        var parents = GetParentSnapshot();
        var parentId = parents.TryGetValue(processId, out var node) && node.ParentProcessId > 4
            ? node.ParentProcessId
            : 0;
        var parentName = parentId > 4 && parents.TryGetValue(parentId, out var parent)
            ? parent.ParentProcessName
            : string.Empty;
        var parentChain = BuildParentChain(processId, parents);

        var signer = string.Empty;
        var product = string.Empty;
        var version = string.Empty;
        bool? isSigned = null;

        if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
        {
            try
            {
                var versionInfo = FileVersionInfo.GetVersionInfo(path);
                product = versionInfo.ProductName ?? string.Empty;
                version = versionInfo.FileVersion ?? string.Empty;
            }
            catch (Exception exception) when (exception is
                         IOException or UnauthorizedAccessException or
                         System.Security.SecurityException or InvalidOperationException)
            {
                // Version metadata is optional.
            }

            try
            {
#pragma warning disable SYSLIB0057 // Authenticode signer extraction has no non-obsolete equivalent.
                using var certificate = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
                signer = certificate.Subject ?? string.Empty;
                isSigned = !string.IsNullOrWhiteSpace(signer);
            }
            catch (CryptographicException)
            {
                isSigned = false;
            }
            catch (Exception exception) when (exception is
                         IOException or UnauthorizedAccessException or
                         System.Security.SecurityException or PlatformNotSupportedException)
            {
                // Signature metadata is optional and must not fail the analysis.
            }
        }

        return new ProcessMetadata(
            parentId > 4 ? parentId : null,
            parentName,
            parentChain,
            signer,
            product,
            version,
            isSigned);
    }

    private static string BuildParentChain(
        int processId,
        IReadOnlyDictionary<int, ProcessNode> nodes)
    {
        var parts = new List<string>();
        var current = processId;
        for (var depth = 0; depth < 4; depth++)
        {
            if (!nodes.TryGetValue(current, out var node) || node.ParentProcessId <= 4)
            {
                break;
            }

            var parentId = node.ParentProcessId;
            if (!nodes.TryGetValue(parentId, out var parent))
            {
                parts.Add($"PID {parentId}");
                break;
            }

            parts.Add($"{parent.ParentProcessName} ({parentId})");
            current = parentId;
        }

        return string.Join(" <- ", parts);
    }

    private static IReadOnlyDictionary<int, ProcessNode> GetParentSnapshot()
    {
        lock (ParentSnapshotGate)
        {
            var now = DateTimeOffset.UtcNow;
            if (now - _parentSnapshotUtc < ParentSnapshotLifetime)
            {
                return _parentSnapshot;
            }

            _parentSnapshot = OperatingSystem.IsWindows()
                ? ReadParentSnapshot()
                : new Dictionary<int, ProcessNode>();
            _parentSnapshotUtc = now;
            return _parentSnapshot;
        }
    }

    private static Dictionary<int, ProcessNode> ReadParentSnapshot()
    {
        var nodes = new Dictionary<int, ProcessNode>();
        var snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
        if (snapshot == InvalidHandleValue)
        {
            return nodes;
        }

        try
        {
            var entry = new ProcessEntry32 { dwSize = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32First(snapshot, ref entry))
            {
                return nodes;
            }

            do
            {
                var processId = unchecked((int)entry.th32ProcessID);
                var parentId = unchecked((int)entry.th32ParentProcessID);
                if (processId > 4)
                {
                    nodes[processId] = new ProcessNode(parentId, entry.szExeFile ?? string.Empty);
                }
            }
            while (Process32Next(snapshot, ref entry));
        }
        finally
        {
            _ = CloseHandle(snapshot);
        }

        return nodes;
    }

    private const uint Th32csSnapProcess = 0x00000002;
    private static readonly IntPtr InvalidHandleValue = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private readonly record struct ProcessNode(int ParentProcessId, string ParentProcessName);

    private sealed record ProcessMetadata(
        int? ParentProcessId,
        string ParentProcessName,
        string ParentChain,
        string SignerName,
        string ProductName,
        string FileVersion,
        bool? IsSigned);

    private sealed record CachedProcessInfo(ProcessMetadata Metadata, DateTimeOffset ResolvedUtc);
}
