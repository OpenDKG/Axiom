// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Axiom.UI.ViewModels;

namespace Axiom.UI.Views;

public partial class AgentsView : UserControl
{
    public AgentsView()
    {
        InitializeComponent();
    }

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

    private void OnCopyProtectedAgentClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: ProtectedAgent agent })
        {
            return;
        }

        CopyText(string.Join(
            Environment.NewLine,
            $"Agent: {agent.KindText}",
            $"Target: {agent.TargetText}",
            $"Status: {agent.DisplayStatus}",
            $"Detail: {agent.Detail}",
            $"Process running: {agent.ProcessRunning}",
            $"Trust required: {agent.TrustRequired}"));
    }

    private void OnCopySessionClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: AgentSessionRow session })
        {
            return;
        }

        CopyText(string.Join(
            Environment.NewLine,
            $"Provider: {session.Provider}",
            $"Title: {session.Title}",
            $"Workspace: {session.Workspace}",
            $"Last seen: {session.LastSeen}",
            $"Live: {session.Live}"));
    }

    private static void CopyText(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return;
        }

        try
        {
            Clipboard.SetText(text);
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
