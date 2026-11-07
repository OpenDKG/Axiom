// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics.CodeAnalysis;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Axiom.Infrastructure.Windows.IpHelper;
using Axiom.UI.Avalonia;

namespace Axiom.Desktop.Avalonia.Windows;

[SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "The Avalonia application lifetime owns shutdown.")]
public partial class App : Application
{
    private ShellViewModel? _shell;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            _shell = new ShellViewModel(new IpHelperConnectionSource(), new AvaloniaUiTimerFactory());
            desktop.MainWindow = new MainWindow { DataContext = _shell };
            _shell.Start();
            desktop.Exit += (_, _) => _shell.Dispose();
        }

        base.OnFrameworkInitializationCompleted();
    }
}
