// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Axiom.Infrastructure.Windows.ProcessIdentity;

/// <summary>
/// Local process metadata for the AI evidence package. It reads the Windows process table, image
/// version/signature metadata and WMI service ownership. It never reads file contents, packet
/// payloads or credentials, and command lines are sanitised before they leave the service.
/// </summary>
public sealed partial class ProcessMetadataProvider
{
    private static readonly TimeSpan MetadataLifetime = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan WmiLifetime = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan ParentLifetime = TimeSpan.FromSeconds(2);
    private static readonly Regex SecretArgument = new(
        @"(?i)(--?(?:password|passwd|pwd|token|secret|api[_-]?key|authorization|bearer)\s+)([^\s""']+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex SecretAssignment = new(
        @"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|authorization|bearer)(\s*[=:]\s*)([^\s""']+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly ConcurrentDictionary<string, CachedMetadata> _metadataCache =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentDictionary<string, CachedImageMetadata> _imageCache =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly object _wmiGate = new();
    private WmiSnapshot _wmi = WmiSnapshot.Empty;
    private DateTimeOffset _wmiUtc = DateTimeOffset.MinValue;

    private readonly object _parentGate = new();
    private IReadOnlyDictionary<int, ProcessNode> _parents = new Dictionary<int, ProcessNode>();
    private DateTimeOffset _parentsUtc = DateTimeOffset.MinValue;

    public ProcessMetadata Resolve(int processId, string executablePath)
    {
        var key = $"{processId}|{executablePath}";
        var now = DateTimeOffset.UtcNow;
        if (_metadataCache.TryGetValue(key, out var cached) &&
            now - cached.ResolvedUtc < MetadataLifetime)
        {
            return cached.Metadata;
        }

        var metadata = Query(processId, executablePath);
        _metadataCache[key] = new CachedMetadata(metadata, now);

        if (_metadataCache.Count > 512)
        {
            foreach (var pair in _metadataCache)
            {
                if (now - pair.Value.ResolvedUtc > MetadataLifetime)
                {
                    _metadataCache.TryRemove(pair.Key, out _);
                }
            }
        }

        return metadata;
    }

    private ProcessMetadata Query(int processId, string executablePath)
    {
        var parents = GetParents();
        var wmi = GetWmi(processId);
        var parentId = parents.TryGetValue(processId, out var node) && node.ParentProcessId > 4
            ? node.ParentProcessId
            : 0;
        var parentName = parentId > 4 && parents.TryGetValue(parentId, out var parent)
            ? parent.ProcessName
            : string.Empty;
        var parentChain = BuildParentChain(processId, parents, wmi.Services);

        var commandLine = wmi.CommandLines.TryGetValue(processId, out var rawCommandLine)
            ? SanitizeCommandLine(rawCommandLine)
            : string.Empty;
        var hostedServices = wmi.Services.TryGetValue(processId, out var services)
            ? string.Join(", ", services.Take(8))
            : string.Empty;
        var parentHostedServices = parentId > 4 && wmi.Services.TryGetValue(parentId, out var parentServices)
            ? string.Join(", ", parentServices.Take(8))
            : string.Empty;

        var (signer, signatureStatus, product, version) = ResolveImageMetadata(executablePath);

        return new ProcessMetadata(
            parentId > 4 ? parentId : null,
            parentName,
            parentChain,
            commandLine,
            signer,
            signatureStatus,
            product,
            version,
            parentHostedServices,
            hostedServices);
    }

    private (string Signer, string SignatureStatus, string Product, string Version) ResolveImageMetadata(string executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
        {
            return (string.Empty, "Unavailable", string.Empty, string.Empty);
        }

        long writeTicks = 0;
        try
        {
            writeTicks = File.GetLastWriteTimeUtc(executablePath).Ticks;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Fall back to un-timestamped cache entry.
        }

        if (_imageCache.TryGetValue(executablePath, out var cached) &&
            cached.LastWriteTicks == writeTicks)
        {
            return (cached.Signer, cached.SignatureStatus, cached.Product, cached.Version);
        }

        var product = string.Empty;
        var version = string.Empty;
        try
        {
            var versionInfo = FileVersionInfo.GetVersionInfo(executablePath);
            product = versionInfo.ProductName ?? string.Empty;
            version = versionInfo.FileVersion ?? string.Empty;
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or
                     System.Security.SecurityException or InvalidOperationException)
        {
            // Version metadata is optional.
        }

        var (signer, signatureStatus) = VerifySignature(executablePath);
        var entry = new CachedImageMetadata(signer, signatureStatus, product, version, writeTicks);
        _imageCache[executablePath] = entry;

        if (_imageCache.Count > 512)
        {
            foreach (var key in _imageCache.Keys.Take(128))
            {
                _imageCache.TryRemove(key, out _);
            }
        }

        return (signer, signatureStatus, product, version);
    }

    private static string BuildParentChain(
        int processId,
        IReadOnlyDictionary<int, ProcessNode> parents,
        IReadOnlyDictionary<int, List<string>> services)
    {
        var parts = new List<string>();
        var current = processId;
        for (var depth = 0; depth < 6; depth++)
        {
            if (!parents.TryGetValue(current, out var node) || node.ParentProcessId <= 4)
            {
                break;
            }

            var parentId = node.ParentProcessId;
            if (!parents.TryGetValue(parentId, out var parent))
            {
                parts.Add($"PID {parentId}");
                break;
            }

            var serviceText = services.TryGetValue(parentId, out var names) && names.Count > 0
                ? $" [{string.Join(", ", names.Take(3))}]"
                : string.Empty;
            parts.Add($"{parent.ProcessName}{serviceText} ({parentId})");
            current = parentId;
        }

        return string.Join(" <- ", parts);
    }

    private static string SanitizeCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return string.Empty;
        }

        var text = commandLine.Trim();
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(profile))
        {
            text = text.Replace(profile, "%USERPROFILE%", StringComparison.OrdinalIgnoreCase);
        }

        text = SecretArgument.Replace(text, "$1***");
        text = SecretAssignment.Replace(text, "$1$2***");
        return text.Length <= 512 ? text : text[..512] + "…";
    }

    private static (string Signer, string Status) VerifySignature(string path)
    {
        try
        {
            var status = VerifyAuthenticode(path);
            var signer = ReadSignerSubject(path);
            return status switch
            {
                0 => (signer, "Valid"),
                unchecked((uint)0x800B0100) => ("", "Unsigned"),
                _ => (signer, "Untrusted"),
            };
        }
        catch (Exception exception) when (exception is
                     CryptographicException or IOException or UnauthorizedAccessException or
                     System.Security.SecurityException or PlatformNotSupportedException)
        {
            return ("", "Unavailable");
        }
    }

    private static string ReadSignerSubject(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // Authenticode signer extraction has no non-obsolete equivalent.
            using var certificate = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            return certificate.Subject ?? string.Empty;
        }
        catch (CryptographicException)
        {
            return string.Empty;
        }
    }

    private static uint VerifyAuthenticode(string path)
    {
        var fileInfo = new WinTrustFileInfo
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            pcwszFilePath = path,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);
            var trustData = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = 2, // WTD_UI_NONE
                fdwRevocationChecks = 0, // WTD_REVOKE_NONE
                dwUnionChoice = 1, // WTD_CHOICE_FILE
                pFile = fileInfoPtr,
                dwStateAction = 1, // WTD_STATEACTION_VERIFY
                dwProvFlags = 0,
            };

            var trustDataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());
            try
            {
                Marshal.StructureToPtr(trustData, trustDataPtr, fDeleteOld: false);
                var action = WinTrustActionGenericVerifyV2;
                var result = WinVerifyTrust(IntPtr.Zero, ref action, trustDataPtr);

                // Preserve hWVTStateData populated by WinVerifyTrust before closing the state handle.
                var verifyState = Marshal.PtrToStructure<WinTrustData>(trustDataPtr);
                verifyState.dwStateAction = 2; // WTD_STATEACTION_CLOSE
                Marshal.StructureToPtr(verifyState, trustDataPtr, fDeleteOld: false);
                _ = WinVerifyTrust(IntPtr.Zero, ref action, trustDataPtr);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(trustDataPtr);
            }
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPtr);
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    private IReadOnlyDictionary<int, ProcessNode> GetParents()
    {
        lock (_parentGate)
        {
            var now = DateTimeOffset.UtcNow;
            if (now - _parentsUtc < ParentLifetime)
            {
                return _parents;
            }

            _parents = ReadParents();
            _parentsUtc = now;
            return _parents;
        }
    }

    private static Dictionary<int, ProcessNode> ReadParents()
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

    private WmiSnapshot GetWmi(int processId)
    {
        lock (_wmiGate)
        {
            var now = DateTimeOffset.UtcNow;
            if (now - _wmiUtc >= WmiLifetime)
            {
                _wmi = ReadWmi();
                _wmiUtc = now;
            }
            else if (processId > 4 &&
                     !_wmi.SeenProcessIds.Contains(processId) &&
                     now - _wmiUtc >= TimeSpan.FromSeconds(5))
            {
                // A process may have started after the last snapshot. Refresh once for a genuinely
                // unseen PID, then record it so processes with empty/protected command lines do not
                // re-trigger WMI queries every 5 seconds.
                _wmi = ReadWmi();
                _wmiUtc = now;
            }

            if (processId > 4)
            {
                _wmi.SeenProcessIds.Add(processId);
            }

            return _wmi;
        }
    }

    private static WmiSnapshot ReadWmi()
    {
        var seenProcessIds = new HashSet<int>();
        var commandLines = new Dictionary<int, string>();
        var services = new Dictionary<int, List<string>>();

        try
        {
            using var processSearcher = new ManagementObjectSearcher(
                "SELECT ProcessId, CommandLine FROM Win32_Process");
            using var processResults = processSearcher.Get();
            foreach (ManagementObject item in processResults)
            {
                using (item)
                {
                    var processId = ToInt(item["ProcessId"]);
                    if (processId <= 4)
                    {
                        continue;
                    }

                    seenProcessIds.Add(processId);
                    if (item["CommandLine"] is string commandLine && !string.IsNullOrWhiteSpace(commandLine))
                    {
                        commandLines[processId] = commandLine;
                    }
                }
            }
        }
        catch (Exception exception) when (exception is
                     ManagementException or UnauthorizedAccessException or
                     PlatformNotSupportedException or InvalidOperationException or COMException)
        {
            // WMI can be disabled or unavailable; the rest of the evidence remains valid.
        }

        try
        {
            using var serviceSearcher = new ManagementObjectSearcher(
                "SELECT Name, ProcessId FROM Win32_Service");
            using var serviceResults = serviceSearcher.Get();
            foreach (ManagementObject item in serviceResults)
            {
                using (item)
                {
                    var processId = ToInt(item["ProcessId"]);
                    var name = item["Name"] as string;
                    if (processId <= 4 || string.IsNullOrWhiteSpace(name))
                    {
                        continue;
                    }

                    seenProcessIds.Add(processId);
                    if (!services.TryGetValue(processId, out var names))
                    {
                        names = [];
                        services[processId] = names;
                    }

                    if (!names.Contains(name, StringComparer.OrdinalIgnoreCase))
                    {
                        names.Add(name);
                    }
                }
            }
        }
        catch (Exception exception) when (exception is
                     ManagementException or UnauthorizedAccessException or
                     PlatformNotSupportedException or InvalidOperationException or COMException)
        {
            // Service ownership is optional.
        }

        return new WmiSnapshot(seenProcessIds, commandLines, services);
    }

    private static int ToInt(object? value)
    {
        try
        {
            return value is null ? 0 : Convert.ToInt32(value, CultureInfo.InvariantCulture);
        }
        catch (Exception exception) when (exception is FormatException or InvalidCastException or OverflowException)
        {
            return 0;
        }
    }

    private const uint Th32csSnapProcess = 0x00000002;
    private static readonly IntPtr InvalidHandleValue = new(-1);
    private static readonly Guid WinTrustActionGenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

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

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint WinVerifyTrust(
        IntPtr hwnd,
        ref Guid actionId,
        IntPtr trustData);

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

    private sealed record ProcessNode(int ParentProcessId, string ProcessName);

    private sealed record WmiSnapshot(
        HashSet<int> SeenProcessIds,
        IReadOnlyDictionary<int, string> CommandLines,
        IReadOnlyDictionary<int, List<string>> Services)
    {
        public static WmiSnapshot Empty { get; } = new(
            [],
            new Dictionary<int, string>(),
            new Dictionary<int, List<string>>());
    }

    private sealed record CachedMetadata(ProcessMetadata Metadata, DateTimeOffset ResolvedUtc);

    private sealed record CachedImageMetadata(
        string Signer,
        string SignatureStatus,
        string Product,
        string Version,
        long LastWriteTicks);
}

/// <summary>Resolved metadata for one process, with empty strings where Windows exposes nothing.</summary>
public sealed record ProcessMetadata(
    int? ParentProcessId,
    string ParentProcessName,
    string ParentChain,
    string CommandLine,
    string SignerName,
    string SignatureStatus,
    string ProductName,
    string FileVersion,
    string ParentHostedServices,
    string HostedServices);
