// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading;
using System.Windows;
using Application = System.Windows.Application;
using System.Windows.Interop;
using System.Windows.Media;
using Netpetra.Contracts;
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
    private static string SingleInstanceMutexName => DistributionContext.IsStorePackage
        ? @"Local\Netpetra.Store.Desktop.SingleInstance"
        : @"Local\Netpetra.Desktop.SingleInstance";

    private static string ShowWindowEventName => DistributionContext.IsStorePackage
        ? @"Local\Netpetra.Store.Desktop.Show"
        : @"Local\Netpetra.Desktop.Show";

    private BundledServiceHost? _serviceHost;
    private TrayStatusController? _trayStatus;
    private Mutex? _singleInstanceMutex;
    private EventWaitHandle? _showWindowEvent;
    private Thread? _showWindowThread;
    private volatile bool _exiting;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var arguments = e.Args;
        var autostart = HasArgument(arguments, "--autostart");
        var startMinimized = HasArgument(arguments, "--start-minimized") ||
                             (autostart && new StartupSettingsStore().Load().StartMinimized);

        if (!TryAcquireSingleInstance())
        {
            SignalExistingInstance();
            Shutdown();
            return;
        }

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
        if (!OnboardingStore.IsCompleted && !autostart)
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
            writer.WriteLine($"Axiom binding trace enabled {DateTimeOffset.UtcNow:O}");
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
        if (!startMinimized)
        {
            window.Show();
        }

        _trayStatus = new TrayStatusController(window, viewModel, monitor);
    }

    private bool TryAcquireSingleInstance()
    {
        _singleInstanceMutex = new Mutex(
            initiallyOwned: true,
            name: SingleInstanceMutexName,
            createdNew: out var createdNew);
        if (!createdNew)
        {
            _singleInstanceMutex.Dispose();
            _singleInstanceMutex = null;
            return false;
        }

        _showWindowEvent = new EventWaitHandle(
            initialState: false,
            mode: EventResetMode.AutoReset,
            name: ShowWindowEventName);
        _showWindowThread = new Thread(ShowWindowLoop)
        {
            IsBackground = true,
            Name = "Netpetra show-window signal",
        };
        _showWindowThread.Start();
        return true;
    }

    private static void SignalExistingInstance()
    {
        try
        {
            if (EventWaitHandle.TryOpenExisting(ShowWindowEventName, out var existing))
            {
                using (existing)
                {
                    existing.Set();
                }
            }
        }
        catch (Exception exception) when (exception is
                     UnauthorizedAccessException or IOException or WaitHandleCannotBeOpenedException)
        {
        }
    }

    private void ShowWindowLoop()
    {
        var signal = _showWindowEvent;
        if (signal is null)
        {
            return;
        }

        while (!_exiting)
        {
            try
            {
                signal.WaitOne();
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            if (_exiting)
            {
                return;
            }

            try
            {
                Dispatcher.Invoke(() => _trayStatus?.ShowWindow());
            }
            catch (Exception exception) when (exception is
                         InvalidOperationException or TaskCanceledException)
            {
                // The UI thread is shutting down.
            }
        }
    }

    private static bool HasArgument(IEnumerable<string> arguments, string expected) =>
        arguments.Any(argument =>
            string.Equals(argument, expected, StringComparison.OrdinalIgnoreCase));

    protected override void OnExit(ExitEventArgs e)
    {
        _exiting = true;
        _showWindowEvent?.Set();
        _showWindowThread?.Join(TimeSpan.FromMilliseconds(500));
        _showWindowEvent?.Dispose();
        _showWindowEvent = null;

        if (_singleInstanceMutex is not null)
        {
            try
            {
                _singleInstanceMutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
                // The mutex was already released or this instance never owned it.
            }

            _singleInstanceMutex.Dispose();
            _singleInstanceMutex = null;
        }

        _trayStatus?.Dispose();
        _serviceHost?.Dispose();

        foreach (TraceListener listener in PresentationTraceSources.DataBindingSource.Listeners)
        {
            listener.Flush();
        }

        base.OnExit(e);
    }
}
