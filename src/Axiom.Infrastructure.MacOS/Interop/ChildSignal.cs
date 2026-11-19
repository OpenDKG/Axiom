// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace Axiom.Infrastructure.MacOS.Interop;

/// <summary>
/// AppleScript's <c>do shell script … with administrator privileges</c> (the desktop's install
/// prompt) starts the command with SIGCHLD ignored. The .NET runtime, which captured that
/// disposition at startup, then never observes its children exit: every
/// <see cref="System.Diagnostics.Process"/> wait hangs or runs into its timeout (<c>axiomd
/// --install-service</c> reported launchctl as timed out, or hung with zombie launchctl children).
/// Resetting the disposition inside the running process is too late, so the helper commands
/// re-execute themselves once with SIGCHLD back at its default.
/// </summary>
public static class ChildSignal
{
    private const int SigChld = 20; // macOS
    private static readonly IntPtr SigDfl = IntPtr.Zero;
    private const int SigUnblock = 2; // macOS SIG_UNBLOCK
    private const string ReexecVariable = "AXIOM_SIGCHLD_REEXEC";

    /// <summary>
    /// Resets SIGCHLD to the default disposition, unblocks it, and replaces this process with a
    /// fresh copy of itself (same arguments) exactly once. The check cannot be conditional: by the
    /// time managed code runs, the runtime has already replaced an inherited SIG_IGN with its own
    /// handler (and recorded the ignored disposition), so <c>signal()</c> no longer reports it and
    /// children are left as zombies that <see cref="System.Diagnostics.Process"/> never observes.
    /// Only used for the short admin commands, so the extra runtime start is cheap. Returns only
    /// when the re-exec already happened or the exec failed.
    /// </summary>
    public static void ReexecIfChildSignalIgnored(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (!OperatingSystem.IsMacOS() || Environment.GetEnvironmentVariable(ReexecVariable) == "1")
        {
            return;
        }

        var path = Environment.ProcessPath;
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        _ = signal(SigChld, SigDfl);
        var unblock = 1u << (SigChld - 1);
        _ = sigprocmask(SigUnblock, ref unblock, IntPtr.Zero);
        // Environment.SetEnvironmentVariable only changes the managed copy on Unix; execv passes
        // the native environment, so the loop guard must go through libc.
        if (setenv(ReexecVariable, "1", 1) != 0)
        {
            return;
        }

        var argv = new IntPtr[args.Length + 2];
        try
        {
            argv[0] = Marshal.StringToCoTaskMemUTF8(path);
            for (var i = 0; i < args.Length; i++)
            {
                argv[i + 1] = Marshal.StringToCoTaskMemUTF8(args[i]);
            }

            _ = execv(path, argv);
        }
        finally
        {
            foreach (var pointer in argv)
            {
                Marshal.FreeCoTaskMem(pointer);
            }
        }

        // execv only returns on failure: continue in this process (waits may time out).
    }

    [DllImport("libc", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    private static extern int setenv(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string value,
        int overwrite);

    [DllImport("libc")]
    private static extern int sigprocmask(int how, ref uint set, IntPtr oldSet);

    [DllImport("libc")]
    private static extern IntPtr signal(int signum, IntPtr handler);

    [DllImport("libc", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    private static extern int execv([MarshalAs(UnmanagedType.LPUTF8Str)] string path, IntPtr[] argv);
}
