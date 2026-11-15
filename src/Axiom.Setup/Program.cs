// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Setup;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
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
