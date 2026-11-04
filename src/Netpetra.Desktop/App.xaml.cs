// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using Netpetra.Contracts.Monitoring;
using Netpetra.Infrastructure.Windows.IpHelper;
using Netpetra.UI;
using Netpetra.UI.Services;
using Netpetra.UI.ViewModels;
using Netpetra.UI.Views;

namespace Netpetra.Desktop;

[SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "The WPF Application lifetime disposes the service host in OnExit.")]
public partial class App : Application
{
    private BundledServiceHost? _serviceHost;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Some Windows GPU drivers produce a blank WPF client area after a driver reset.
        // Software rendering is slower but always paints; hardware is opt-in for machines
        // where it is known to work.
        if (!string.Equals(
                Environment.GetEnvironmentVariable("NETPETRA_HARDWARE_RENDER"),
                "1",
                StringComparison.Ordinal))
        {
            RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
        }

        ThemeManager.Apply(ThemeSettingsStore.Load());

        ShutdownMode = System.Windows.ShutdownMode.OnExplicitShutdown;
        if (!OnboardingStore.IsCompleted)
        {
            var setup = new FirstRunWindow();
            setup.ShowDialog();
        }

        ShutdownMode = System.Windows.ShutdownMode.OnMainWindowClose;

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

        _serviceHost = new BundledServiceHost();
        useService = useService || _serviceHost.TryStart();

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
        _serviceHost?.Dispose();

        foreach (TraceListener listener in PresentationTraceSources.DataBindingSource.Listeners)
        {
            listener.Flush();
        }

        base.OnExit(e);
    }
}
