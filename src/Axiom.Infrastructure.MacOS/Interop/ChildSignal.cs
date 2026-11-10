// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace Axiom.Infrastructure.MacOS.Interop;

/// <summary>
/// AppleScript's <c>do shell script … with administrator privileges</c> (the desktop's install
/// prompt) starts the command with SIGCHLD ignored. The kernel then reaps children itself and the
/// .NET runtime, which captured that disposition at startup, never observes them exit: every
/// <see cref="System.Diagnostics.Process"/> wait runs into its timeout (<c>axiomd
/// --install-service</c> hung for a minute and reported launchctl as failed). Resetting the
/// disposition inside the running process is too late, so the helper commands re-execute
/// themselves once with SIGCHLD back at its default.
/// </summary>
public static class ChildSignal
{
    private const int SigChld = 20; // macOS
    private static readonly IntPtr SigDfl = IntPtr.Zero;
    private static readonly IntPtr SigIgn = new(1);

    /// <summary>
    /// When SIGCHLD was inherited as ignored, resets it to the default and replaces this process
    /// with a fresh copy of itself (same arguments). Returns only when no re-exec was needed or
    /// the exec failed.
    /// </summary>
    public static void ReexecIfChildSignalIgnored(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (!OperatingSystem.IsMacOS() || Environment.GetEnvironmentVariable("AXIOM_SIGCHLD_REEXEC") == "1")
        {
            return;
        }

        var previous = signal(SigChld, SigDfl);
        if (previous != SigIgn)
        {
            _ = signal(SigChld, previous);
            return;
        }

        var path = Environment.ProcessPath;
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        Environment.SetEnvironmentVariable("AXIOM_SIGCHLD_REEXEC", "1");
        var argv = new string?[args.Length + 2];
        argv[0] = path;
        Array.Copy(args, 0, argv, 1, args.Length);
        argv[^1] = null;
        _ = execv(path, argv);
        // execv only returns on failure: continue in this process (waits may time out).
    }

    [DllImport("libc")]
    private static extern IntPtr signal(int signum, IntPtr handler);

    [DllImport("libc", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    private static extern int execv(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPUTF8Str)] string?[] argv);
}
