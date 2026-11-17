// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Windows.Input;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Threading;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class ContextMenuPlacementTests
{
    [Fact]
    public void A_pointer_opened_context_menu_exposes_its_owner_as_placement_target()
    {
        TestAppBuilder.RunOnUiThread(() =>
        {
            var command = new RecordingCommand();
            var cell = new TextBlock { Text = "row" };
            var row = new Border
            {
                Child = cell,
                DataContext = new RowContext { CopyCommand = command },
            };
            var item = new MenuItem { Header = "Copy" };
            item.Bind(MenuItem.CommandProperty, new Binding(nameof(RowContext.CopyCommand)));
            var menu = new ContextMenu();
            menu.Items.Add(item);
            row.ContextMenu = menu;

            var window = new Window { Width = 400, Height = 300, Content = row };
            window.Show();
            Dispatcher.UIThread.RunJobs();

            cell.RaiseEvent(new ContextRequestedEventArgs());
            Dispatcher.UIThread.RunJobs();

            Assert.True(menu.IsOpen);
            Assert.Same(row, menu.PlacementTarget);
            Assert.Same(command, item.Command);

            menu.Close();
            window.Close();
        });
    }

    private sealed class RowContext
    {
        public ICommand? CopyCommand { get; init; }
    }

    private sealed class RecordingCommand : ICommand
    {
        public event EventHandler? CanExecuteChanged
        {
            add { }
            remove { }
        }

        public bool CanExecute(object? parameter) => true;

        public void Execute(object? parameter)
        {
        }
    }
}
