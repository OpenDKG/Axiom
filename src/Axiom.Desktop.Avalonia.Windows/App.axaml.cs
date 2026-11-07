// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Platform;
using Avalonia.Styling;
using Avalonia.Threading;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.Windows.IpHelper;
using Axiom.Presentation;
using Axiom.UI.Avalonia;

namespace Axiom.Desktop.Avalonia.Windows;

[SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "The Avalonia application lifetime owns shutdown.")]
public partial class App : Application
{
    private const string SingleInstanceMutexName = @"Local\Axiom.Avalonia.Desktop.SingleInstance";
    private const string ShowWindowEventName = @"Local\Axiom.Avalonia.Desktop.Show";

    private ShellViewModel? _shell;
    private BundledServiceHost? _serviceHost;
    private MainWindow? _window;
    private TrayIcon? _tray;
    private Mutex? _singleInstanceMutex;
    private EventWaitHandle? _showWindowEvent;
    private Thread? _showWindowThread;
    private volatile bool _exiting;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var arguments = desktop.Args ?? [];

            if (!TryAcquireSingleInstance())
            {
                SignalExistingInstance();
                desktop.Shutdown();
                return;
            }

            var useService = arguments.Any(argument =>
                string.Equals(argument, "--service", StringComparison.OrdinalIgnoreCase));

            _serviceHost = new BundledServiceHost();
            ServiceStatusProbe? serviceProbe = null;
            IServiceRequestClient? serviceClient = null;
            IConnectionSnapshotSource source;

            if (useService || _serviceHost.TryStart())
            {
                var client = new ServicePipeClient();
                source = new ServiceSnapshotSource(client);
                serviceProbe = new ServiceStatusProbe(client);
                serviceClient = client;
            }
            else
            {
                source = new IpHelperConnectionSource();
            }

            MainWindow? window = null;
            var interaction = new AvaloniaUserInteraction(() => window);
            var theme = new WindowsThemeService();
            RequestedThemeVariant = theme.Current == UiTheme.Light ? ThemeVariant.Light : ThemeVariant.Dark;
            var autostart = new WindowsAutostartService();
            _shell = new ShellViewModel(
                source,
                new AvaloniaUiTimerFactory(),
                serviceProbe,
                serviceClient,
                interaction,
                new ProcessActions(),
                theme,
                autostart,
                new DpapiApiKeyProtector(),
                new WindowsDnsAdapterHelper());

            window = new MainWindow { DataContext = _shell };
            _window = window;
            desktop.MainWindow = window;

            CreateTrayIcon(desktop);
            _shell.Start();

            var autostartArgument = HasArgument(arguments, "--autostart");
            var startMinimized = HasArgument(arguments, "--start-minimized") ||
                                 (autostartArgument && new StartupSettingsStore().Load().StartMinimized);

            window.Show();
            if (startMinimized)
            {
                window.Hide();
            }

            desktop.Exit += (_, _) => Cleanup();
        }

        base.OnFrameworkInitializationCompleted();
    }

    private static bool HasArgument(IEnumerable<string> arguments, string expected) =>
        arguments.Any(argument =>
            string.Equals(argument, expected, StringComparison.OrdinalIgnoreCase));

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
            Name = "Axiom show-window signal",
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

            ShowWindow();
        }
    }

    private void ShowWindow() => Dispatcher.UIThread.Post(() =>
    {
        if (_window is null)
        {
            return;
        }

        _window.Show();
        _window.WindowState = WindowState.Normal;
        _window.Activate();
    });

    private void CreateTrayIcon(IClassicDesktopStyleApplicationLifetime desktop)
    {
        try
        {
            var icon = new WindowIcon(AssetLoader.Open(
                new Uri("avares://Axiom.UI.Avalonia/Assets/axiom-icon.png")));
            _tray = new TrayIcon
            {
                Icon = icon,
                ToolTipText = "Axiom — local-only network monitor",
                IsVisible = true,
            };

            var menu = new NativeMenu();
            var openItem = new NativeMenuItem("Open Axiom");
            openItem.Click += (_, _) => ShowWindow();

            var notificationsItem = new NativeMenuItem("Show problem notifications")
            {
                ToggleType = MenuItemToggleType.CheckBox,
                IsChecked = TraySettingsStore.Enabled,
            };
            notificationsItem.Click += (_, _) =>
                TraySettingsStore.SetEnabled(notificationsItem.IsChecked);

            var exitItem = new NativeMenuItem("Exit Axiom");
            exitItem.Click += (_, _) => desktop.Shutdown();

            menu.Add(openItem);
            menu.Add(notificationsItem);
            menu.Add(new NativeMenuItemSeparator());
            menu.Add(exitItem);
            _tray.Menu = menu;
            _tray.Clicked += (_, _) => ShowWindow();
        }
#pragma warning disable CA1031 // A missing tray must not prevent the monitor from opening.
        catch (Exception)
#pragma warning restore CA1031
        {
            _tray = null;
        }
    }

    private void Cleanup()
    {
        _exiting = true;
        _showWindowEvent?.Set();
        _showWindowThread?.Join(TimeSpan.FromMilliseconds(500));
        _showWindowEvent?.Dispose();
        _showWindowEvent = null;
        _singleInstanceMutex?.Dispose();
        _singleInstanceMutex = null;

        if (_tray is not null)
        {
            _tray.IsVisible = false;
            _tray.Dispose();
            _tray = null;
        }

        _shell?.Dispose();
        _serviceHost?.Dispose();
    }
}
