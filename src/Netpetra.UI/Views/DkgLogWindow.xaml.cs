// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;
using System.Windows.Automation;
using System.Windows.Input;

namespace Netpetra.UI.Views;

public partial class DkgLogWindow : Window
{
    private Point _dragStart;
    private bool _pressed;
    private bool _dragging;

    public DkgLogWindow(string text)
    {
        InitializeComponent();
        LogText.Text = text;
    }

    private void OnTitleBarMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            _pressed = false;
            ToggleMaximize();
            e.Handled = true;
            return;
        }

        if (e.LeftButton == MouseButtonState.Pressed)
        {
            _pressed = true;
            _dragStart = e.GetPosition(this);
        }
    }

    private void OnTitleBarMouseMove(object sender, MouseEventArgs e)
    {
        if (!_pressed || _dragging || e.LeftButton != MouseButtonState.Pressed)
        {
            return;
        }

        var position = e.GetPosition(this);
        if (Math.Abs(position.X - _dragStart.X) < SystemParameters.MinimumHorizontalDragDistance &&
            Math.Abs(position.Y - _dragStart.Y) < SystemParameters.MinimumVerticalDragDistance)
        {
            return;
        }

        _dragging = true;
        _pressed = false;
        try
        {
            DragMove();
        }
        finally
        {
            _dragging = false;
        }
    }

    private void OnTitleBarMouseLeftButtonUp(object sender, MouseButtonEventArgs e) => _pressed = false;

    private void ToggleMaximize() => WindowState = WindowState == WindowState.Maximized
        ? WindowState.Normal
        : WindowState.Maximized;

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Maximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        if (MaximizeButton is null)
        {
            return;
        }

        var maximized = WindowState == WindowState.Maximized;
        MaximizeButton.Content = maximized ? "❐" : "□";
        MaximizeButton.ToolTip = maximized ? "Restore" : "Maximize";
        AutomationProperties.SetName(MaximizeButton,
            maximized ? "Restore DKG diagnostic log" : "Maximize DKG diagnostic log");
    }
}
