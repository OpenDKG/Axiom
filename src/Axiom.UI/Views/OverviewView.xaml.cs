// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Axiom.UI.ViewModels;

namespace Axiom.UI.Views;

public partial class OverviewView : UserControl
{
    public OverviewView() => InitializeComponent();

    private void OnDataGridPreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (sender is not DataGrid grid ||
            ItemsControl.ContainerFromElement(grid, e.OriginalSource as DependencyObject) is not DataGridRow row)
        {
            return;
        }

        grid.SelectedItem = row.Item;
        row.IsSelected = true;
    }

    private void OnCopyDetailValueClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: ActivityDetailRow detail })
        {
            return;
        }

        try
        {
            Clipboard.SetText(detail.Value);
        }
        catch (ExternalException)
        {
            // Clipboard is temporarily owned by another process.
        }
        catch (InvalidOperationException)
        {
            // The UI is shutting down or the clipboard is unavailable.
        }
    }
}
