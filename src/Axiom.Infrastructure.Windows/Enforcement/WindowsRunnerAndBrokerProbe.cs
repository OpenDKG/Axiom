// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace Axiom.Infrastructure.Windows.Enforcement;

/// <summary>Result of probing Windows OS runner and broker isolation primitives (Stage E3).</summary>
public sealed record ManagedRunnerFeasibilityReport(
    bool JobObjectAvailable,
    bool ReparsePointDefenseAvailable,
    string DefaultClaimedBoundary,
    IReadOnlyList<string> RuntimeLimitations);

/// <summary>
/// Stage E3 Windows probe: verifies non-privileged Job Object creation and full ancestor
/// reparse-point / junction / symlink inspection for <see cref="Core.Enforcement.TrustedFileBroker"/>
/// without blanket ACL rewrites, SYSTEM ownership changes, or kernel drivers.
/// </summary>
public static class WindowsRunnerAndBrokerProbe
{
    public static bool HasReparsePointInAncestry(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return true;
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return true;
        }

        if (fullPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return true;
        }

        var current = fullPath;
        while (!string.IsNullOrEmpty(current))
        {
            if (IsReparsePointEntry(current))
            {
                return true;
            }

            current = Path.GetDirectoryName(current);
        }

        return false;
    }

    public static ManagedRunnerFeasibilityReport ProbeCurrentHost()
    {
        var jobOk = CanCreateAnonymousJobObject();
        return new ManagedRunnerFeasibilityReport(
            JobObjectAvailable: jobOk,
            ReparsePointDefenseAvailable: true,
            DefaultClaimedBoundary: "HOST_DENY_VERIFIED",
            RuntimeLimitations:
            [
                "Same-user agent runtimes launched outside the runner can still access user-readable files directly unless relocated behind an explicit low-privilege AppContainer or separate principal.",
                "Arbitrary third-party CLI hosts (OpenCode, Claude Code, Codex, Node/Python toolchains) are not assumed AppContainer-compatible without per-host runner testing.",
                "Blanket ACL deny entries, SYSTEM ownership transfers, TLS MITM, and custom kernel drivers remain explicitly forbidden per ADR 0010/0012.",
            ]);
    }

    private static bool IsReparsePointEntry(string path)
    {
        try
        {
            if (!File.Exists(path) && !Directory.Exists(path))
            {
                return false;
            }

            var attributes = File.GetAttributes(path);
            return (attributes & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // Fail closed on inaccessible or suspicious path segments.
            return true;
        }
    }

    private static bool CanCreateAnonymousJobObject()
    {
        var handle = CreateJobObjectW(IntPtr.Zero, null);
        if (handle == IntPtr.Zero)
        {
            return false;
        }

        _ = CloseHandle(handle);
        return true;
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string? lpName);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);
}
