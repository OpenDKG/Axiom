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

namespace Axiom.Desktop.Avalonia.Linux;

[SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "The Avalonia application lifetime owns shutdown.")]
public partial class App : Application
{
    private ShellViewModel? _shell;
    private MainWindow? _window;
    private TrayIcon? _tray;
    private LinuxSingleInstance? _singleInstance;

    /// <summary>Lock taken by <see cref="Program.Main"/> before Avalonia starts; owned (disposed) by the app.</summary>
    internal static LinuxSingleInstance? SingleInstance { get; set; }
    private LinuxProtectionSetup? _protection;
    private NativeMenuItem? _daemonStatusItem;
    private readonly List<NativeMenuItem> _installItems = [];
    private bool _trayWanted;
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

        // The lock was taken in Program.Main; bind the show socket first, before anything heavy,
        // so a second launch finds it as early as possible (it retries once after 300 ms).
        _singleInstance = SingleInstance ?? new LinuxSingleInstance();
        SingleInstance = null;
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

        // Linux always talks to the axiomd systemd daemon over /run/axiom/axiom.sock. There is
        // no in-process fallback monitor: pages show the offline state until the daemon runs.
        var client = new ServicePipeClient();
        IConnectionSnapshotSource source = new ServiceSnapshotSource(client);
        var serviceProbe = new ServiceStatusProbe(client);

        MainWindow? window = null;
        var interaction = new AvaloniaUserInteraction(() => window);
        var theme = new LinuxThemeService();
        theme.AttachToPlatform(this);
        RequestedThemeVariant = LinuxThemeService.VariantFor(theme.Current);
        var protector = new SecretServiceApiKeyProtector();

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
            new LinuxAutostartService(),
            protector,
            new LinuxDnsAdapterHelper(),
            new AvaloniaSecurityDialogs(() => window),
            new AvaloniaShellActions(() => desktop.Shutdown()),
            new AvaloniaBlackboxDialogs(() => window),
            new Axiom.Persistence.AgentSessionReader(),
            visualEffects: null,
            restoreNetwork: networkRecovery.RestoreAsync);

        window = new MainWindow { DataContext = _shell };
        _window = window;
        desktop.MainWindow = window;
        // Upstream 1.3.1: pages and traffic sampling pause while the window is hidden or minimized.
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
            if (!ShouldHideToTray(_allowExit, _tray is not null, TraySettingsStore.Enabled))
            {
                return;
            }

            // With a StatusNotifier host, closing the window keeps Axiom in the tray; without one
            // (stock GNOME) there is nothing to come back from, so closing quits.
            args.Cancel = true;
            window.Hide();
        };

        _protection = new LinuxProtectionSetup(serviceProbe, interaction);
        _protection.Changed += (_, _) => Dispatcher.UIThread.Post(UpdateStatusItems);

        _shell.SetPresentationVisible(window.IsVisible && window.WindowState != WindowState.Minimized);
        _shell.Start();
        StartNetworkRecovery(networkRecovery);

        var autostartArgument = HasArgument(arguments, "--autostart");
        var startMinimized = HasArgument(arguments, "--start-minimized") ||
                             (autostartArgument && new StartupSettingsStore().Load().StartMinimized);

        window.Show();
        _trayWanted = StatusNotifierProbe.ShouldCreateTray(
            StatusNotifierProbe.IsWatcherPresent(),
            Environment.GetEnvironmentVariable(StatusNotifierProbe.OverrideVariable));
        StartupLog.Write("tray", _trayWanted ? "StatusNotifierWatcher present; creating tray icon" : "no StatusNotifierWatcher on the session bus; no tray, close = quit");
        if (_trayWanted)
        {
            CreateTrayIcon(desktop);
        }

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

        // Once the service runs, the action item reads as state.
        var daemonRunning = _protection.Daemon == DaemonState.Running;
        foreach (var item in _installItems)
        {
            item.Header = MenuHeaders.Install(daemonRunning);
            item.IsEnabled = !daemonRunning;
        }
    }

    /// <summary>Close hides to the tray only when a tray exists and the user kept it enabled (pure; unit-tested).</summary>
    public static bool ShouldHideToTray(bool exiting, bool trayPresent, bool trayEnabled) =>
        !exiting && trayPresent && trayEnabled;

    /// <summary>Menu wording for the setup action (pure; unit-tested).</summary>
    public static class MenuHeaders
    {
        public static string Install(bool daemonRunning) =>
            daemonRunning ? "Service: running" : "Install Background Service…";
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
            var installItem = new NativeMenuItem(MenuHeaders.Install(false));
            installItem.Click += (_, _) => InstallDaemon();
            _installItems.Add(installItem);

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
            menu.Add(installItem);
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

        _ = desktop;
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
