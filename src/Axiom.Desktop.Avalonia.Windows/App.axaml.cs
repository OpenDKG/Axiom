// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics.CodeAnalysis;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
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
            IConnectionSnapshotSource source;

            if (useService || _serviceHost.TryStart())
            {
                var client = new ServicePipeClient();
                source = new ServiceSnapshotSource(client);
                serviceProbe = new ServiceStatusProbe(client);
            }
            else
            {
                source = new IpHelperConnectionSource();
            }

            _shell = new ShellViewModel(source, new AvaloniaUiTimerFactory(), serviceProbe);
            desktop.MainWindow = new MainWindow { DataContext = _shell };
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
