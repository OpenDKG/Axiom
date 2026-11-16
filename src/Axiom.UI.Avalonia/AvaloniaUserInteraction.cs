// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Avalonia host services: native modal confirmations, the platform save dialog, clipboard and
/// external links. A missing owner or clipboard is reported as a failure instead of pretending.
/// </summary>
public sealed class AvaloniaUserInteraction(Func<Window?> ownerProvider) : IUserInteraction
{
    private static IBrush Background => AxiomDialogTheme.WindowBackground;
    private static IBrush Border => AxiomDialogTheme.Border;
    private static IBrush PrimaryText => AxiomDialogTheme.TextPrimary;

    public async Task<bool> ConfirmAsync(
        string title,
        string message,
        string confirmLabel,
        bool destructive,
        CancellationToken cancellationToken)
    {
        var owner = ownerProvider();
        if (owner is null)
        {
            return false;
        }

        var result = false;
        var dialog = CreateDialog(title);
        var cancel = CreateButton("Cancel", destructive: false);
        var confirm = CreateButton(confirmLabel, destructive);

        cancel.Click += (_, _) => dialog.Close();
        confirm.Click += (_, _) =>
        {
            result = true;
            dialog.Close();
        };

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 10,
            Children = { cancel, confirm },
        };

        dialog.Content = BuildContent(message, buttons);
        await dialog.ShowDialog(owner).ConfigureAwait(true);
        return result && !cancellationToken.IsCancellationRequested;
    }

    public async Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken)
    {
        var owner = ownerProvider();
        if (owner is null)
        {
            return;
        }

        var dialog = CreateDialog(title);
        var close = CreateButton("Close", destructive: false);
        close.Click += (_, _) => dialog.Close();
        close.HorizontalAlignment = HorizontalAlignment.Right;

        dialog.Content = BuildContent(message, close);
        await dialog.ShowDialog(owner).ConfigureAwait(true);
    }

    public async Task ShowDocumentAsync(
        string title,
        string document,
        CancellationToken cancellationToken)
    {
        var owner = ownerProvider();
        if (owner is null)
        {
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();

        var dialog = new Window
        {
            Title = title,
            Width = 760,
            Height = 620,
            MinWidth = 460,
            MinHeight = 320,
            CanResize = true,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Background = Background,
            Foreground = PrimaryText,
        };

        var text = new SelectableTextBlock
        {
            Text = document,
            TextWrapping = TextWrapping.Wrap,
            FontSize = 12,
            Foreground = PrimaryText,
        };

        var scroll = new ScrollViewer
        {
            Content = text,
            Padding = new Thickness(0, 0, 12, 0),
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        };

        var copy = CreateButton("Copy", destructive: false);
        var close = CreateButton("Close", destructive: false);
        copy.Click += async (_, _) =>
        {
            var clipboard = dialog.Clipboard;
            if (clipboard is not null)
            {
                await clipboard.SetValueAsync(DataFormat.Text, document).ConfigureAwait(true);
            }
        };
        close.Click += (_, _) => dialog.Close();

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 10,
            Margin = new Thickness(0, 14, 0, 0),
            Children = { copy, close },
        };

        var root = new Grid
        {
            RowDefinitions = new RowDefinitions("*,Auto"),
            Margin = new Thickness(20),
        };
        Grid.SetRow(scroll, 0);
        Grid.SetRow(buttons, 1);
        root.Children.Add(scroll);
        root.Children.Add(buttons);

        dialog.Content = root;
        await dialog.ShowDialog(owner).ConfigureAwait(true);
    }

    public async Task<string?> PickSaveFileAsync(
        string suggestedFileName,
        string extension,
        string typeName,
        CancellationToken cancellationToken)
    {
        var owner = ownerProvider();
        if (owner is null)
        {
            return null;
        }

        var file = await owner.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Save Axiom export",
            SuggestedFileName = suggestedFileName,
            DefaultExtension = extension.TrimStart('.'),
            ShowOverwritePrompt = true,
            FileTypeChoices =
            [
                new FilePickerFileType(typeName)
                {
                    Patterns = [$"*.{extension.TrimStart('.')}"],
                },
            ],
        }).ConfigureAwait(true);

        cancellationToken.ThrowIfCancellationRequested();
        return file?.TryGetLocalPath();
    }

    public async Task<string?> PickOpenFileAsync(
        string title,
        string extension,
        string typeName,
        CancellationToken cancellationToken)
    {
        var owner = ownerProvider();
        if (owner is null)
        {
            return null;
        }

        var files = await owner.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = title,
            AllowMultiple = false,
            FileTypeFilter =
            [
                new FilePickerFileType(typeName)
                {
                    Patterns = [$"*.{extension.TrimStart('.')}"],
                },
            ],
        }).ConfigureAwait(true);

        cancellationToken.ThrowIfCancellationRequested();
        return files.Count == 0 ? null : files[0].TryGetLocalPath();
    }

    public async Task<string?> PickFolderAsync(string title, CancellationToken cancellationToken)
    {
        var owner = ownerProvider();
        if (owner is null)
        {
            return null;
        }

        var folders = await owner.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = title,
            AllowMultiple = false,
        }).ConfigureAwait(true);

        cancellationToken.ThrowIfCancellationRequested();
        return folders.Count == 0 ? null : folders[0].TryGetLocalPath();
    }

    public async Task CopyTextAsync(string text, CancellationToken cancellationToken)
    {
        var owner = ownerProvider()
            ?? throw new InvalidOperationException("No window is available for the clipboard.");
        var clipboard = owner.Clipboard
            ?? throw new InvalidOperationException("The clipboard is not available on this platform.");

        await clipboard.SetValueAsync(DataFormat.Text, text).ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();
    }

    public Task OpenExternalAsync(string url, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        return Task.CompletedTask;
    }

    private static Window CreateDialog(string title) => new()
    {
        Title = title,
        Width = 520,
        SizeToContent = SizeToContent.Height,
        MinHeight = 170,
        CanResize = false,
        WindowStartupLocation = WindowStartupLocation.CenterOwner,
        Background = Background,
        Foreground = PrimaryText,
    };

    private static StackPanel BuildContent(string message, Control action)
    {
        var panel = new StackPanel { Spacing = 16, Margin = new Thickness(22) };
        panel.Children.Add(new SelectableTextBlock
        {
            Text = message,
            TextWrapping = TextWrapping.Wrap,
            Foreground = PrimaryText,
            FontSize = 13,
        });
        panel.Children.Add(action);
        return panel;
    }

    private static Button CreateButton(string label, bool destructive)
    {
        var button = new Button
        {
            Content = label,
            MinWidth = 96,
            Padding = new Thickness(14, 7),
            HorizontalContentAlignment = HorizontalAlignment.Center,
            CornerRadius = new CornerRadius(6),
        };
        if (destructive)
        {
            button.Classes.Add("danger");
        }
        else if (!string.Equals(label, "Cancel", StringComparison.OrdinalIgnoreCase))
        {
            button.Classes.Add("primary");
        }

        return button;
    }
}
