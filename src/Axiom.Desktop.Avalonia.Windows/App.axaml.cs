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
using Axiom.Contracts.NetworkRecovery;
using Axiom.Infrastructure.Windows.IpHelper;
using Axiom.Infrastructure.Windows.Modules;
using Axiom.Presentation;
using Axiom.UI.Avalonia;

namespace Axiom.Desktop.Avalonia.Windows;

[SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "The Avalonia application lifetime owns shutdown.")]
public partial class App : Application
{
    private const string SingleInstanceMutexName = @"Local\Axiom.Desktop.SingleInstance";
    private const string ShowWindowEventName = @"Local\Axiom.Desktop.Show";

    private ShellViewModel? _shell;
    private BundledServiceHost? _serviceHost;
    private MainWindow? _window;
    private TrayIcon? _tray;
    private ModuleWindowHider? _moduleWindowHider;
    private Mutex? _singleInstanceMutex;
    private EventWaitHandle? _showWindowEvent;
    private Thread? _showWindowThread;
    private volatile bool _exiting;
    private volatile bool _allowExit;

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

            // Provision Axiom-managed hooks for detected harnesses without a second setup dialog.
            // Existing user-authored hooks are preserved; host-owned trust stays host-owned.
            try
            {
                AgentHookMaintenance.ProvisionDetectedHooks();
            }
            catch
            {
                // Hook maintenance is best-effort and must not block startup.
            }

            // A complete install must end protected: persist block mode where the guard reads it
            // and prove it with the self-test. Runs off the UI thread so startup stays responsive.
            _ = Task.Run(() =>
            {
                try
                {
                    var protection = ProtectionProvisioner.ProvisionAtStartup();
                    if (protection is not null)
                    {
                        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                        PrivacyShieldProvisioner.WriteSettings(localAppData);
                        PrivacyShieldProvisioner.ApplyAsync(CancellationToken.None).GetAwaiter().GetResult();
                        TraderShieldProvisioner.ApplyToFile(Path.Combine(localAppData, "hermes", "config.yaml"));
                        HermesPluginSettings.ApplyToFile(Path.Combine(localAppData, "hermes", "config.yaml"));
                    }
                }
                catch
                {
                    // Protection provisioning is best-effort; the status file records the outcome.
                }
            });

            var useService = arguments.Any(argument =>
                string.Equals(argument, "--service", StringComparison.OrdinalIgnoreCase));

            _serviceHost = new BundledServiceHost();
            ServiceStatusProbe? serviceProbe = null;
            IServiceRequestClient? serviceClient = null;
            IConnectionSnapshotSource source;

            // Always try the bundled service so an installed package works with --service even
            // when no service was started externally. The explicit flag still forces the pipe path.
            var bundledService = _serviceHost.TryStart();
            if (useService || bundledService)
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
            RequestedThemeVariant = theme.Current switch
            {
                UiTheme.Light => ThemeVariant.Light,
                UiTheme.DarkMidnight => AxiomThemeVariants.DarkMidnight,
                UiTheme.LightWarm => AxiomThemeVariants.LightWarm,
                UiTheme.GlassDark => AxiomThemeVariants.GlassDark,
                UiTheme.GlassLight => AxiomThemeVariants.GlassLight,
                _ => ThemeVariant.Dark,
            };
            var autostart = new WindowsAutostartService();
            var listenerInspector = new WindowsLoopbackListenerInspector();
            var visualEffects = new WindowsVisualEffectsService();
            NetworkRecoveryClient? networkRecovery = null;
            if (serviceClient is not null)
            {
                // Recovery needs the service because firewall and DNS writes require elevation.
                // It uses a longer request timeout than the read-only UI commands.
                networkRecovery = new NetworkRecoveryClient(
                    new ServicePipeClient(requestTimeout: NetworkRecoveryClient.DefaultRequestTimeout));
            }

            var protector = new DpapiApiKeyProtector();
            _shell = new ShellViewModel(
                source,
                new AvaloniaUiTimerFactory(),
                serviceProbe,
                serviceClient,
                interaction,
                new ProcessActions(),
                theme,
                autostart,
                protector,
                new WindowsDnsAdapterHelper(),
                new AvaloniaSecurityDialogs(() => window),
                new AvaloniaShellActions(() => desktop.Shutdown()),
                new AvaloniaBlackboxDialogs(() => window, interaction),
                new Axiom.Persistence.AgentSessionReader(),
                visualEffects,
                networkRecovery is null ? null : networkRecovery.RestoreAsync,
                listenerInspector);

            window = new MainWindow { DataContext = _shell };
            _window = window;
            desktop.MainWindow = window;
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

                // Closing with tray notifications enabled keeps Axiom in the notification area so
                // an alert can still be shown next to the clock.
                args.Cancel = true;
                window.Hide();
            };

            _shell.Start();
            StartNetworkRecovery(networkRecovery);

            var autostartArgument = HasArgument(arguments, "--autostart");
            var startMinimized = HasArgument(arguments, "--start-minimized") ||
                                 (autostartArgument && new StartupSettingsStore().Load().StartMinimized);

            window.Show();
            CreateTrayIcon(desktop);
            _moduleWindowHider = new ModuleWindowHider();
            _moduleWindowHider.Start();

            if (_tray is null)
            {
                // Some shells need the main window to exist before a tray icon can register.
                Dispatcher.UIThread.Post(async () =>
                {
                    await Task.Delay(TimeSpan.FromSeconds(3)).ConfigureAwait(true);
                    if (_tray is null)
                    {
                        CreateTrayIcon(desktop);
                    }
                });
            }

            if (startMinimized && _tray is not null)
            {
                // The desktop lifetime shows MainWindow right after framework initialization, so
                // hiding here would be undone. Post the hide to run once startup has finished.
                Dispatcher.UIThread.Post(window.Hide, DispatcherPriority.Loaded);
            }

            if (!startMinimized && !autostartArgument && !OnboardingStore.IsCompleted)
            {
                Dispatcher.UIThread.Post(async () =>
                    await FirstRunDialog.ShowAsync(window, protector).ConfigureAwait(true));
            }

            desktop.Exit += (_, _) => Cleanup();
        }

        base.OnFrameworkInitializationCompleted();
    }

    /// <summary>
    /// Asks the service to save the machine baseline once. The service also captures at its own
    /// start; this call is an idempotent fallback for a service that was already running. A failure
    /// is logged and later reported truthfully as "no saved state"; it never changes the network.
    /// </summary>
    private static void StartNetworkRecovery(NetworkRecoveryClient? recovery)
    {
        if (recovery is null)
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                var result = await recovery.CaptureAsync(CancellationToken.None).ConfigureAwait(false);
                if (result.Status is not (NetworkRecoveryStatus.Succeeded or NetworkRecoveryStatus.AlreadyCaptured))
                {
                    WriteRecoveryLog(
                        $"Recovery baseline not saved: {result.Status}. " +
                        NetworkRecoveryText.Problems(result.Problems));
                }
            }
            catch (Exception exception) when (exception is
                         InvalidOperationException or UnauthorizedAccessException or IOException)
            {
                WriteRecoveryLog($"Recovery baseline request failed: {exception.Message}");
            }
        });
    }

    private static void WriteRecoveryLog(string message)
    {
        try
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Axiom",
                "network-recovery.log");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.AppendAllText(path, $"{DateTimeOffset.UtcNow:O} {message}\n");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
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
            var tray = new TrayIcon
            {
                Icon = icon,
                ToolTipText = "Axiom - Free Open-Source Network & AI Agent Security",
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
            exitItem.Click += (_, _) =>
            {
                _allowExit = true;
                desktop.Shutdown();
            };

            menu.Add(openItem);
            menu.Add(notificationsItem);
            menu.Add(new NativeMenuItemSeparator());
            menu.Add(exitItem);
            tray.Menu = menu;
            tray.Clicked += (_, _) => ShowWindow();

            // A TrayIcon that is not part of the application's TrayIcons collection is never
            // registered with the shell: it stays invisible without raising an error. Attaching it
            // last also guarantees the icon, tooltip and menu exist before the native icon shows.
            TrayIcon.SetIcons(this, new TrayIcons { tray });
            _tray = tray;
        }
#pragma warning disable CA1031 // A missing tray must not prevent the monitor from opening.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _tray = null;
            try
            {
                var path = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Axiom",
                    "tray-error.log");
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.AppendAllText(path, $"{DateTimeOffset.UtcNow:O} {exception}\n");
            }
            catch (Exception logException) when (logException is IOException or UnauthorizedAccessException)
            {
            }
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
            TrayIcon.SetIcons(this, null);
            _tray.Dispose();
            _tray = null;
        }

        _shell?.Dispose();
        _serviceHost?.Dispose();
        _moduleWindowHider?.Dispose();
        _moduleWindowHider = null;
    }
}
