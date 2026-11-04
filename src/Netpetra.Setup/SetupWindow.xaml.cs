// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;

namespace Netpetra.Setup;

public partial class SetupWindow : Window
{
    private readonly SetupOptions _options;
    private bool _installing;

    public SetupWindow(SetupOptions options)
    {
        InitializeComponent();
        _options = options;
        InstallDirText.Text = options.InstallDir;
        ShortcutCheck.IsChecked = options.CreateShortcut;
        LaunchCheck.IsChecked = options.StartAfterInstall;
        HooksCheck.IsChecked = options.InstallAgentHooks;
    }

    private async void OnInstall(object sender, RoutedEventArgs e)
    {
        if (_installing)
        {
            return;
        }

        _installing = true;
        InstallButton.IsEnabled = false;
        CloseButton.IsEnabled = false;
        LogBox.Clear();

        var options = _options with
        {
            CreateShortcut = ShortcutCheck.IsChecked == true,
            StartAfterInstall = LaunchCheck.IsChecked == true,
            InstallAgentHooks = HooksCheck.IsChecked == true,
        };

        var progress = new Progress<string>(message =>
        {
            LogBox.AppendText(message + Environment.NewLine);
            LogBox.ScrollToEnd();
        });

        var result = await SetupInstaller.InstallAsync(options, progress, CancellationToken.None);
        _installing = false;

        if (result.Success)
        {
            CloseButton.Content = "Close";
            CloseButton.IsEnabled = true;

            if (options.StartAfterInstall)
            {
                Close();
                return;
            }

            MessageBox.Show(this, result.Message, "Netpetra Setup",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            InstallButton.IsEnabled = true;
            CloseButton.IsEnabled = true;
            MessageBox.Show(this, result.Message, "Netpetra Setup failed",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnClose(object sender, RoutedEventArgs e)
    {
        if (!_installing)
        {
            Close();
        }
    }
}
