// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Windows;
using Netpetra.Contracts.Monitoring;
using Netpetra.Infrastructure.Windows.IpHelper;
using Netpetra.UI;
using Netpetra.UI.Services;
using Netpetra.UI.ViewModels;

namespace Netpetra.Desktop;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ThemeManager.Apply(AppTheme.Dark);

        // Opt-in binding diagnostics for manual/automated UI checks:
        //   set NETPETRA_BINDING_TRACE=<log path> before starting the shell.
        var tracePath = Environment.GetEnvironmentVariable("NETPETRA_BINDING_TRACE");
        if (!string.IsNullOrWhiteSpace(tracePath))
        {
            var writer = new StreamWriter(tracePath, append: false) { AutoFlush = true };
            var listener = new TextWriterTraceListener(writer, "NetpetraBindingTrace");
            PresentationTraceSources.Refresh();
            PresentationTraceSources.DataBindingSource.Listeners.Add(listener);
            PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.Warning;
            writer.WriteLine($"Netpetra binding trace enabled {DateTimeOffset.UtcNow:O}");
        }

        var useService = e.Args.Any(argument =>
            string.Equals(argument, "--service", StringComparison.OrdinalIgnoreCase));

        IConnectionSnapshotSource source = useService
            ? new ServiceSnapshotSource(new ServicePipeClient())
            : new IpHelperConnectionSource();

        ConnectionSourceRegistry.Source = source;

        var monitor = new ConnectionMonitor(source);
        var viewModel = new MainViewModel(monitor);
        var window = new MainWindow(viewModel);

        MainWindow = window;
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        foreach (TraceListener listener in PresentationTraceSources.DataBindingSource.Listeners)
        {
            listener.Flush();
        }

        base.OnExit(e);
    }
}
