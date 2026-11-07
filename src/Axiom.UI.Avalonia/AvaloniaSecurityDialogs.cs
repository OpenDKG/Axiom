// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Modal setup forms for the Security page. Each dialog writes nothing itself; it only returns the
/// edited settings so the page can apply them after the user confirms.
/// </summary>
public sealed class AvaloniaSecurityDialogs(Func<Window?> ownerProvider) : ISecurityDialogService
{
    private static readonly IBrush Background = new SolidColorBrush(Color.Parse("#161B22"));
    private static readonly IBrush Foreground = new SolidColorBrush(Color.Parse("#E6EDF3"));
    private static readonly IBrush Muted = new SolidColorBrush(Color.Parse("#9BA9B8"));

    public async Task<ReputationSettings?> EditReputationAsync(
        ReputationSettings current,
        CancellationToken cancellationToken)
    {
        var owner = ownerProvider();
        if (owner is null)
        {
            return null;
        }

        var enabled = new CheckBox
        {
            Content = "Enable hash-only VirusTotal lookups",
            IsChecked = current.Enabled,
            Foreground = Foreground,
        };
        var key = new TextBox
        {
            Text = current.ApiKey,
            PasswordChar = '●',
            PlaceholderText = "VirusTotal API key (stored with DPAPI)",
        };

        var window = CreateWindow("Reputation provider");
        var result = default(ReputationSettings);
        var cancel = Button("Cancel", false);
        var save = Button("Save", true);
        cancel.Click += (_, _) => window.Close();
        save.Click += (_, _) =>
        {
            result = new ReputationSettings(enabled.IsChecked == true, key.Text?.Trim() ?? string.Empty);
            window.Close();
        };

        window.Content = Form(
            "Hash-only lookup. No file is uploaded; only the SHA-256 is sent after an explicit scan action.",
            [enabled, Label("API key"), key],
            [cancel, save]);

        await window.ShowDialog(owner).ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    public async Task<CommunityFeedSettings?> EditCommunityAsync(
        CommunityFeedSettings current,
        CancellationToken cancellationToken)
    {
        var owner = ownerProvider();
        if (owner is null)
        {
            return null;
        }

        var enabled = new CheckBox
        {
            Content = "Enable the HTTPS community feed",
            IsChecked = current.Enabled,
            Foreground = Foreground,
        };
        var url = new TextBox { Text = current.Url, PlaceholderText = "https://… feed URL" };
        var token = new TextBox
        {
            Text = current.Token,
            PasswordChar = '●',
            PlaceholderText = "Optional bearer token (stored with DPAPI)",
        };

        var window = CreateWindow("Community feed");
        var result = default(CommunityFeedSettings);
        var cancel = Button("Cancel", false);
        var save = Button("Save", true);
        cancel.Click += (_, _) => window.Close();
        save.Click += (_, _) =>
        {
            result = new CommunityFeedSettings(
                enabled.IsChecked == true,
                url.Text?.Trim() ?? string.Empty,
                token.Text?.Trim() ?? string.Empty);
            window.Close();
        };

        window.Content = Form(
            "Entries are community evidence, never an automatic verdict. Axiom does not upload reports.",
            [enabled, Label("Feed URL"), url, Label("Token (optional)"), token],
            [cancel, save]);

        await window.ShowDialog(owner).ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    public async Task<bool?> ChooseAgentHookInstallationAsync(CancellationToken cancellationToken)
    {
        var owner = ownerProvider();
        if (owner is null)
        {
            return null;
        }

        var window = CreateWindow("Install agent hooks");
        bool? result = null;
        var partial = Button("Partial (no files)", false);
        var complete = Button("Complete installation", true);
        var cancel = Button("Cancel", false);
        partial.Click += (_, _) =>
        {
            result = false;
            window.Close();
        };
        complete.Click += (_, _) =>
        {
            result = true;
            window.Close();
        };
        cancel.Click += (_, _) => window.Close();

        window.Content = Form(
            "Axiom can provision its managed hooks for detected harnesses. Partial installation " +
            "changes no OpenCode, OpenChamber, Codex, Claude Code, Cursor, Copilot, Gemini, Windsurf, " +
            "Cline, ZCode or DeepSeek Harness hook file. Complete installation backs up existing " +
            "managed files and verifies that unrelated user state was not changed.",
            [],
            [cancel, partial, complete]);

        await window.ShowDialog(owner).ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    private static Window CreateWindow(string title) => new()
    {
        Title = title,
        Width = 560,
        SizeToContent = SizeToContent.Height,
        MinHeight = 180,
        CanResize = false,
        WindowStartupLocation = WindowStartupLocation.CenterOwner,
        Background = Background,
        Foreground = Foreground,
    };

    private static StackPanel Form(string description, IReadOnlyList<Control> fields, IReadOnlyList<Control> actions)
    {
        var panel = new StackPanel { Spacing = 10, Margin = new Thickness(22) };
        panel.Children.Add(new TextBlock
        {
            Text = description,
            TextWrapping = TextWrapping.Wrap,
            Foreground = Muted,
            FontSize = 11,
        });
        foreach (var field in fields)
        {
            panel.Children.Add(field);
        }

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 8,
        };
        foreach (var action in actions)
        {
            buttons.Children.Add(action);
        }

        panel.Children.Add(buttons);
        return panel;
    }

    private static TextBlock Label(string text) => new()
    {
        Text = text,
        Foreground = Muted,
        FontSize = 10,
    };

    private static Button Button(string label, bool primary) => new()
    {
        Content = label,
        MinWidth = 100,
        Padding = new Thickness(12, 6),
        Background = primary
            ? new SolidColorBrush(Color.Parse("#1F6FEB"))
            : new SolidColorBrush(Color.Parse("#1A2430")),
        Foreground = Foreground,
        BorderBrush = new SolidColorBrush(Color.Parse("#2E3A47")),
        BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(6),
    };
}
