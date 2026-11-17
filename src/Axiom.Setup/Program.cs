// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Threading;

namespace Axiom.Setup;

internal static class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBox(nint hWnd, string text, string caption, uint type);

    /// <summary>
    /// A global mutex keeps a second setup from running next to the first. On a shared or
    /// non-interactive account the mutex can exist with an ACL this process cannot open (seen on
    /// the CI runner: "Access to the path 'Global\AxiomSetup.SingleInstance' is denied"), and an
    /// unhandled exception there would abort the installer. Fall back to a session-local guard so
    /// setup still runs, and say so on stderr.
    /// </summary>
    private static Mutex CreateSingleInstanceMutex(out bool created)
    {
        try
        {
            return new Mutex(initiallyOwned: true, @"Global\AxiomSetup.SingleInstance", out created);
        }
        catch (UnauthorizedAccessException)
        {
            Console.Error.WriteLine(
                "Axiom Setup: the global single-instance guard is not accessible from this account; " +
                "continuing with a session-local guard.");
            return new Mutex(initiallyOwned: true, @"Local\AxiomSetup.SingleInstance", out created);
        }
    }

    [STAThread]
    private static void Main(string[] args)
    {
        var options = SetupOptions.Parse(args);

        // A second setup instance used to run concurrently with the first, each making its own
        // multi-GB upgrade backup and fighting over the service. One instance only. In silent mode a
        // modal box would hang an unattended install (there is nobody to dismiss it), so the message
        // goes to stderr and the process exits instead of waiting.
        using var single = CreateSingleInstanceMutex(out var created);
        if (!created)
        {
            const string busy = "Axiom Setup is already running. Wait for the current installation to finish; "
                                + "running a second copy duplicates the upgrade backup and can freeze the machine.";
            if (options.Silent)
            {
                Console.Error.WriteLine(busy);
            }
            else
            {
                _ = MessageBox(nint.Zero, busy, "Axiom Setup", 0x00000040);
            }

            Environment.ExitCode = 3;
            return;
        }

        if (options.Silent)
        {
            if (options.Uninstall)
            {
                var uninstall = SetupInstaller
                    .UninstallAsync(options, progress: null, CancellationToken.None)
                    .GetAwaiter()
                    .GetResult();
                Console.WriteLine(uninstall.Message);
                Environment.ExitCode = uninstall.Success ? 0 : 1;
                return;
            }

            if (!options.AcceptRisk)
            {
                Console.Error.WriteLine(
                    "Axiom is a development build. Pass --accept-risk with --silent to confirm that you use it at your own risk.");
                Environment.ExitCode = 2;
                return;
            }

            var result = SetupInstaller
                .InstallAsync(options, progress: null, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            if (!result.Success || result.PartialSuccess)
            {
                // Write the reason / partial-success warnings and the tail of the log so automated callers see what stopped optional steps.
                Console.Error.WriteLine((result.Success ? "Axiom setup partial success: " : "Axiom setup failed: ") + result.Message);
                if (!string.IsNullOrWhiteSpace(result.Warning))
                {
                    Console.Error.WriteLine(result.Warning);
                }

                foreach (var line in result.Log.TakeLast(20))
                {
                    Console.Error.WriteLine("  " + line);
                }
            }

            Environment.ExitCode = result.Success ? 0 : 1;
            return;
        }

        using var window = new SetupNativeWindow(options);
        Environment.ExitCode = window.Run();
    }
}
