// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics.CodeAnalysis;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Styling;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.Windows.IpHelper;
using Axiom.Presentation;
using Axiom.UI.Avalonia;

namespace Axiom.Desktop.Avalonia.Windows;

[SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "The Avalonia application lifetime owns shutdown.")]
public partial class App : Application
{
    private ShellViewModel? _shell;
    private BundledServiceHost? _serviceHost;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var arguments = desktop.Args ?? [];
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
            desktop.MainWindow = window;
            _shell.Start();
            desktop.Exit += (_, _) =>
            {
                _shell.Dispose();
                _serviceHost?.Dispose();
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}
