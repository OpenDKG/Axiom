// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;

namespace Axiom.Setup;

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
        CompleteRadio.IsChecked = options.CompleteInstallation;
        PartialRadio.IsChecked = !options.CompleteInstallation;
        AgreeCheck.Checked += OnAgreementChanged;
        AgreeCheck.Unchecked += OnAgreementChanged;
        InstallButton.IsEnabled = false;
        Loaded += (_, _) =>
        {
            ContentScroll.ScrollToTop();
            AgreeCheck.Focus();
        };
    }

    private void OnAgreementChanged(object sender, RoutedEventArgs e)
    {
        InstallButton.IsEnabled = !_installing && AgreeCheck.IsChecked == true;
    }

    private async void OnInstall(object sender, RoutedEventArgs e)
    {
        if (_installing || AgreeCheck.IsChecked != true)
        {
            return;
        }

        _installing = true;
        InstallButton.IsEnabled = false;
        AgreeCheck.IsEnabled = false;
        CloseButton.IsEnabled = false;
        LogBox.Clear();

        var options = _options with
        {
            CreateShortcut = ShortcutCheck.IsChecked == true,
            StartAfterInstall = LaunchCheck.IsChecked == true,
            CompleteInstallation = CompleteRadio.IsChecked == true,
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
            AgreeCheck.IsEnabled = true;

            if (result.Warning is { Length: > 0 } warning)
            {
                MessageBox.Show(this, warning, "Axiom Setup", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            if (options.StartAfterInstall)
            {
                Close();
                return;
            }

            MessageBox.Show(this, result.Message, "Axiom Setup",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            AgreeCheck.IsEnabled = true;
            InstallButton.IsEnabled = AgreeCheck.IsChecked == true;
            CloseButton.IsEnabled = true;
            MessageBox.Show(this, result.Message, "Axiom Setup failed",
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
