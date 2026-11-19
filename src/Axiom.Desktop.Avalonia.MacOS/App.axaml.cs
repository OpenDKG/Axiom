// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics.CodeAnalysis;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Platform;
using Avalonia.Threading;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Presentation;
using Axiom.UI.Avalonia;

namespace Axiom.Desktop.Avalonia.MacOS;

[SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "The Avalonia application lifetime owns shutdown.")]
public partial class App : Application
{
    private ShellViewModel? _shell;
    private MainWindow? _window;
    private TrayIcon? _tray;
    private MacSingleInstance? _singleInstance;
    private MacProtectionSetup? _protection;
    private NativeMenuItem? _daemonStatusItem;
    private NativeMenuItem? _filterStatusItem;
    private readonly List<NativeMenuItem> _installItems = [];
    private readonly List<NativeMenuItem> _activateItems = [];
    private readonly CancellationTokenSource _cancellation = new();
    private volatile bool _allowExit;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            try
            {
                Start(desktop);
            }
            catch (Exception exception)
            {
                StartupLog.Write("startup", exception);
                throw;
            }
        }

        base.OnFrameworkInitializationCompleted();
    }

    private void Start(IClassicDesktopStyleApplicationLifetime desktop)
    {
        var arguments = desktop.Args ?? [];
        StartupLog.Write(
            "startup",
            $"Axiom {typeof(App).Assembly.GetName().Version} pid={Environment.ProcessId} base={AppContext.BaseDirectory}");

        // Lock and show-socket first, before anything heavy, so a second launch finds the socket
        // as early as possible; the second launch retries once after 300 ms for the remaining gap.
        _singleInstance = new MacSingleInstance();
        if (!_singleInstance.TryAcquire())
        {
            var delivered = _singleInstance.SignalExistingAsync(MacSingleInstance.SignalRetryDelay).GetAwaiter().GetResult();
            StartupLog.Write("startup", $"Another Axiom instance is running; show signal delivered={delivered}.");
            _singleInstance = null;
            desktop.Shutdown();
            return;
        }

        _singleInstance.Listen(ShowWindow);

        try
        {
            AgentHookMaintenance.ProvisionDetectedHooks();
        }
#pragma warning disable CA1031 // Hook maintenance is best-effort and must not block startup.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            StartupLog.Write("hooks", exception.Message);
        }

        // macOS always talks to the axiomd launchd daemon over /var/run/axiom/axiom.sock. There is
        // no in-process fallback monitor: pages show the offline state until the daemon runs.
        var client = new ServicePipeClient();
        IConnectionSnapshotSource source = new ServiceSnapshotSource(client);
        var serviceProbe = new ServiceStatusProbe(client);

        MainWindow? window = null;
        var interaction = new AvaloniaUserInteraction(() => window);
        var theme = new MacThemeService();
        theme.AttachToPlatform(this);
        RequestedThemeVariant = MacThemeService.VariantFor(theme.Current);
        var protector = new KeychainApiKeyProtector();

        // Recovery needs the daemon because DNS and filter-rule writes require root. It uses a
        // longer request timeout than the read-only UI commands.
        var networkRecovery = new NetworkRecoveryClient(
            new ServicePipeClient(requestTimeout: NetworkRecoveryClient.DefaultRequestTimeout));

        _shell = new ShellViewModel(
            source,
            new AvaloniaUiTimerFactory(),
            serviceProbe,
            client,
            interaction,
            new ProcessActions(),
            theme,
            new MacAutostartService(),
            protector,
            new MacDnsAdapterHelper(),
            new AvaloniaSecurityDialogs(() => window),
            new AvaloniaShellActions(() => desktop.Shutdown()),
            new AvaloniaBlackboxDialogs(() => window),
            new Axiom.Persistence.AgentSessionReader(),
            visualEffects: null,
            restoreNetwork: networkRecovery.RestoreAsync);

        window = new MainWindow { DataContext = _shell };
        _window = window;
        desktop.MainWindow = window;
        window.PropertyChanged += (_, change) =>
        {
            if (change.Property == Visual.IsVisibleProperty || change.Property == Window.WindowStateProperty)
            {
                _shell?.SetPresentationVisible(window.IsVisible && window.WindowState != WindowState.Minimized);
            }
        };
        AxiomAlertService.Configure(
            () => _window,
            ShowWindow,
            (page, focusApps) => _shell?.NavigateToPage(page, focusApps));
        desktop.ShutdownRequested += (_, _) => _allowExit = true;
        window.Closing += (_, args) =>
        {
            if (_allowExit || _tray is null || !TraySettingsStore.Enabled)
            {
                return;
            }

            // macOS convention: closing the window keeps Axiom in the menu bar.
            args.Cancel = true;
            window.Hide();
        };

        if (this.TryGetFeature<IActivatableLifetime>() is { } activatable)
        {
            // Clicking the Dock icon of a running app with no visible window reopens it.
            activatable.Activated += (_, eventArgs) =>
            {
                if (eventArgs.Kind == ActivationKind.Reopen)
                {
                    ShowWindow();
                }
            };
        }

        _protection = new MacProtectionSetup(serviceProbe, new FilterExtensionManager(), interaction);
        _protection.Changed += (_, _) => Dispatcher.UIThread.Post(UpdateStatusItems);

        _shell.Start();
        StartNetworkRecovery(networkRecovery);

        var autostartArgument = HasArgument(arguments, "--autostart");
        var startMinimized = HasArgument(arguments, "--start-minimized") ||
                             (autostartArgument && new StartupSettingsStore().Load().StartMinimized);

        window.Show();
        CreateApplicationMenu(desktop);
        CreateTrayIcon(desktop);

        if (startMinimized && _tray is not null)
        {
            Dispatcher.UIThread.Post(window.Hide, DispatcherPriority.Loaded);
        }

        var firstRun = !startMinimized && !autostartArgument && !OnboardingStore.IsCompleted;
        Dispatcher.UIThread.Post(async () =>
        {
            try
            {
                if (firstRun)
                {
                    await FirstRunDialog.ShowAsync(window, protector).ConfigureAwait(true);
                }

                if (autostartArgument)
                {
                    await _protection.RefreshAsync(_cancellation.Token).ConfigureAwait(true);
                }
                else
                {
                    await _protection.RunStartupChecksAsync(_cancellation.Token).ConfigureAwait(true);
                }
            }
            catch (OperationCanceledException)
            {
            }
#pragma warning disable CA1031 // A failed setup check must never take the window down.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                StartupLog.Write("setup", exception);
            }
        });

        desktop.Exit += (_, _) => Cleanup();
    }

    /// <summary>
    /// Asks the daemon to save the machine baseline once. The daemon also captures at its own
    /// start; this call is an idempotent fallback for a daemon that was already running. A failure
    /// is logged and later reported truthfully as "no saved state"; it never changes the network.
    /// </summary>
    private static void StartNetworkRecovery(NetworkRecoveryClient recovery)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                var result = await recovery.CaptureAsync(CancellationToken.None).ConfigureAwait(false);
                if (result.Status is not (NetworkRecoveryStatus.Succeeded or NetworkRecoveryStatus.AlreadyCaptured))
                {
                    StartupLog.Write(
                        "recovery",
                        $"Recovery baseline not saved: {result.Status}. " + NetworkRecoveryText.Problems(result.Problems));
                }
            }
            catch (Exception exception) when (exception is
                         InvalidOperationException or UnauthorizedAccessException or IOException)
            {
                StartupLog.Write("recovery", $"Recovery baseline request failed: {exception.Message}");
            }
        });
    }

    private static bool HasArgument(IEnumerable<string> arguments, string expected) =>
        arguments.Any(argument =>
            string.Equals(argument, expected, StringComparison.OrdinalIgnoreCase));

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

    private void ShowAbout()
    {
        ShowWindow();
        Dispatcher.UIThread.Post(() => _shell?.NavigateToPage(typeof(SettingsPageViewModel)));
    }

    private void InstallDaemon() => Dispatcher.UIThread.Post(async () =>
    {
        if (_protection is null)
        {
            return;
        }

        ShowWindow();
        try
        {
            await _protection.RefreshAsync(_cancellation.Token).ConfigureAwait(true);
            if (_protection.Daemon == DaemonState.Running)
            {
                await new AvaloniaUserInteraction(() => _window)
                    .ShowMessageAsync("Axiom background service", _protection.DaemonSummary, _cancellation.Token)
                    .ConfigureAwait(true);
                return;
            }

            await _protection.InstallDaemonAsync(fromStartup: false, _cancellation.Token).ConfigureAwait(true);
        }
#pragma warning disable CA1031 // A menu action must report, not crash.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            StartupLog.Write("daemon", exception);
        }
    });

    private void ActivateFilter() => Dispatcher.UIThread.Post(async () =>
    {
        if (_protection is null)
        {
            return;
        }

        ShowWindow();
        try
        {
            await _protection.ActivateFilterAsync(_cancellation.Token).ConfigureAwait(true);
        }
#pragma warning disable CA1031 // A menu action must report, not crash.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            StartupLog.Write("sysext", exception);
        }
    });

    private void UpdateStatusItems()
    {
        if (_protection is null)
        {
            return;
        }

        if (_daemonStatusItem is not null)
        {
            _daemonStatusItem.Header = _protection.DaemonSummary;
        }

        if (_filterStatusItem is not null)
        {
            _filterStatusItem.Header = _protection.FilterSummary;
        }

        // Review #25: once the service runs / the filter is on, the action items read as state.
        var daemonRunning = _protection.Daemon == DaemonState.Running;
        var filterRunning = _protection.Filter is { IsRunning: true };
        foreach (var item in _installItems)
        {
            item.Header = MenuHeaders.Install(daemonRunning);
            item.IsEnabled = !daemonRunning;
        }

        foreach (var item in _activateItems)
        {
            item.Header = MenuHeaders.Activate(filterRunning);
            item.IsEnabled = !filterRunning;
        }
    }

    /// <summary>Menu wording for the two setup actions (pure; unit-tested).</summary>
    public static class MenuHeaders
    {
        public static string Install(bool daemonRunning) =>
            daemonRunning ? "Service: running" : "Install Background Service…";

        public static string Activate(bool filterRunning) =>
            filterRunning ? "Filter: on" : "Turn On Network Filter…";
    }

    /// <summary>The application menu next to the Apple menu. Avalonia appends Hide/Quit itself.</summary>
    private void CreateApplicationMenu(IClassicDesktopStyleApplicationLifetime desktop)
    {
        try
        {
            var menu = new NativeMenu();
            var about = new NativeMenuItem("About Axiom");
            about.Click += (_, _) => ShowAbout();
            menu.Add(about);
            menu.Add(new NativeMenuItemSeparator());
            var install = new NativeMenuItem(MenuHeaders.Install(false));
            install.Click += (_, _) => InstallDaemon();
            menu.Add(install);
            _installItems.Add(install);
            var filter = new NativeMenuItem(MenuHeaders.Activate(false));
            filter.Click += (_, _) => ActivateFilter();
            menu.Add(filter);
            _activateItems.Add(filter);
            NativeMenu.SetMenu(this, menu);
            _ = desktop;
        }
#pragma warning disable CA1031 // A missing native menu must not prevent the window from opening.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            StartupLog.Write("menu", exception);
        }
    }

    private void CreateTrayIcon(IClassicDesktopStyleApplicationLifetime desktop)
    {
        try
        {
            var icon = new WindowIcon(AssetLoader.Open(
                new Uri("avares://Axiom.UI.Avalonia/Assets/axiom-icon.png")));
            var tray = new TrayIcon
            {
                Icon = icon,
                ToolTipText = "Axiom - Free Open-Source Network & AI Agent Security",
                IsVisible = true,
            };

            var menu = new NativeMenu();
            var openItem = new NativeMenuItem("Open Axiom");
            openItem.Click += (_, _) => ShowWindow();

            _daemonStatusItem = new NativeMenuItem("Background service: checking…") { IsEnabled = false };
            _filterStatusItem = new NativeMenuItem("Network filter: checking…") { IsEnabled = false };
            var installItem = new NativeMenuItem(MenuHeaders.Install(false));
            installItem.Click += (_, _) => InstallDaemon();
            _installItems.Add(installItem);
            var filterItem = new NativeMenuItem(MenuHeaders.Activate(false));
            filterItem.Click += (_, _) => ActivateFilter();
            _activateItems.Add(filterItem);

            var notificationsItem = new NativeMenuItem("Show problem notifications")
            {
                ToggleType = MenuItemToggleType.CheckBox,
                IsChecked = TraySettingsStore.Enabled,
            };
            notificationsItem.Click += (_, _) =>
                TraySettingsStore.SetEnabled(notificationsItem.IsChecked);

            var exitItem = new NativeMenuItem("Quit Axiom");
            exitItem.Click += (_, _) =>
            {
                _allowExit = true;
                desktop.Shutdown();
            };

            menu.Add(openItem);
            menu.Add(new NativeMenuItemSeparator());
            menu.Add(_daemonStatusItem);
            menu.Add(_filterStatusItem);
            menu.Add(installItem);
            menu.Add(filterItem);
            menu.Add(new NativeMenuItemSeparator());
            menu.Add(notificationsItem);
            menu.Add(new NativeMenuItemSeparator());
            menu.Add(exitItem);
            tray.Menu = menu;
            tray.Clicked += (_, _) => ShowWindow();

            TrayIcon.SetIcons(this, new TrayIcons { tray });
            _tray = tray;
        }
#pragma warning disable CA1031 // A missing menu-bar icon must not prevent the monitor from opening.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _tray = null;
            StartupLog.Write("tray", exception);
        }
    }

    private void Cleanup()
    {
        _cancellation.Cancel();
        _singleInstance?.Dispose();
        _singleInstance = null;

        if (_tray is not null)
        {
            _tray.IsVisible = false;
            TrayIcon.SetIcons(this, null);
            _tray.Dispose();
            _tray = null;
        }

        _shell?.Dispose();
        _cancellation.Dispose();
    }
}
