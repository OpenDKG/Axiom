// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Threading;

namespace Axiom.Setup;

internal static class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBox(nint hWnd, string text, string caption, uint type);

    [STAThread]
    private static void Main(string[] args)
    {
        // A second setup instance used to run concurrently with the first, each making its own
        // multi-GB upgrade backup and fighting over the service. One instance only.
        using var single = new Mutex(initiallyOwned: true, @"Global\AxiomSetup.SingleInstance", out var created);
        if (!created)
        {
            _ = MessageBox(
                nint.Zero,
                "Axiom Setup is already running. Wait for the current installation to finish; running a second copy duplicates the upgrade backup and can freeze the machine.",
                "Axiom Setup",
                0x00000040);
            Environment.ExitCode = 3;
            return;
        }

        var options = SetupOptions.Parse(args);
        if (options.Silent)
        {
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
            if (!result.Success)
            {
                // Silent mode used to exit 1 with no reason at all. Write the failure and the tail
                // of the log so the caller (and the lab log) can see what stopped the install.
                Console.Error.WriteLine("Axiom setup failed: " + result.Message);
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
