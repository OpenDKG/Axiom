// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;

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
            Environment.ExitCode = result.Success ? 0 : 1;
            return;
        }

        var application = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };

        application.Resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri("pack://application:,,,/Axiom.UI;component/Themes/Dark.xaml", UriKind.Absolute),
        });
        application.Resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri("pack://application:,,,/Axiom.UI;component/Themes/Controls.xaml", UriKind.Absolute),
        });

        application.Run(new SetupWindow(options));
    }
}
