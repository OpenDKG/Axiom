// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;
using System.Windows.Automation;
using System.Windows.Input;
using Netpetra.UI.ViewModels;

namespace Netpetra.UI;

public partial class MainWindow : Window
{
    private Point _titleBarDragStart;
    private bool _titleBarPressed;
    private bool _dragging;

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
    }

    private void OnTitleBarMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            _titleBarPressed = false;
            ToggleMaximize();
            e.Handled = true;
            return;
        }

        if (e.LeftButton == MouseButtonState.Pressed)
        {
            _titleBarPressed = true;
            _titleBarDragStart = e.GetPosition(this);
        }
    }

    private void OnTitleBarMouseMove(object sender, MouseEventArgs e)
    {
        if (!_titleBarPressed || _dragging || e.LeftButton != MouseButtonState.Pressed)
        {
            return;
        }

        var position = e.GetPosition(this);
        if (Math.Abs(position.X - _titleBarDragStart.X) < SystemParameters.MinimumHorizontalDragDistance &&
            Math.Abs(position.Y - _titleBarDragStart.Y) < SystemParameters.MinimumVerticalDragDistance)
        {
            return;
        }

        _dragging = true;
        _titleBarPressed = false;
        try
        {
            DragMove();
        }
        finally
        {
            _dragging = false;
        }
    }

    private void OnTitleBarMouseLeftButtonUp(object sender, MouseButtonEventArgs e) =>
        _titleBarPressed = false;

    private void OnMinimizeClicked(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximizeClicked(object sender, RoutedEventArgs e) => ToggleMaximize();

    private void OnCloseClicked(object sender, RoutedEventArgs e) => Close();

    private void ToggleMaximize() => WindowState = WindowState == WindowState.Maximized
        ? WindowState.Normal
        : WindowState.Maximized;

    private void OnWindowStateChanged(object sender, EventArgs e)
    {
        if (MaximizeButton is null)
        {
            return;
        }

        var maximized = WindowState == WindowState.Maximized;
        MaximizeButton.Content = maximized ? "❐" : "□";
        MaximizeButton.ToolTip = maximized ? "Restore" : "Maximize";
        AutomationProperties.SetName(MaximizeButton, maximized ? "Restore Netpetra" : "Maximize Netpetra");
    }

    protected override void OnClosed(EventArgs e)
    {
        (DataContext as IDisposable)?.Dispose();
        base.OnClosed(e);
    }
}
