// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Text.Json.Nodes;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;
using Axiom.Contracts.Blackbox;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>Compact Avalonia Blackbox settings and log dialogs. Save is verified by re-reading.</summary>
public sealed class AvaloniaBlackboxDialogs(Func<Window?> ownerProvider, IUserInteraction ui)
    : IBlackboxDialogService
{
    private static readonly string[] Severities = ["info", "low", "medium", "high", "critical"];

    private static IBrush Background => AxiomDialogTheme.WindowBackground;
    private static IBrush Foreground => AxiomDialogTheme.TextPrimary;
    private static IBrush Muted => AxiomDialogTheme.TextMuted;

    public async Task ShowSettingsAsync(BlackboxDashboardClient client, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        var owner = ownerProvider();
        if (owner is null)
        {
            return;
        }

        var window = CreateWindow("Blackbox settings", 660);
        var status = new TextBlock { Text = "Loading settings…", Foreground = Muted, FontSize = 10, TextWrapping = TextWrapping.Wrap };
        var mode = new ComboBox { ItemsSource = new[] { "audit", "block" }, Width = 140 };
        var blockSeverity = new ComboBox { ItemsSource = Severities, Width = 140 };
        var discover = new CheckBox { Content = "Discover", Foreground = Foreground };
        var osv = new CheckBox { Content = "OSV lookup", Foreground = Foreground };
        var report = new CheckBox { Content = "Signed threat sharing", Foreground = Foreground };
        var originalReport = false;
        var paths = new ObservableCollection<string>();
        var pathList = new ListBox
        {
            ItemsSource = paths,
            Height = 120,
            Background = AxiomDialogTheme.SurfaceAlt,
            BorderBrush = AxiomDialogTheme.Border,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            Classes = { "data-list" },
        };
        var pathInput = new TextBox { PlaceholderText = "Absolute file or folder path" };
        var categories = new List<CategoryControls>();
        foreach (var (key, label) in new[]
                 {
                     ("injection", "Injection"),
                     ("escalation", "Escalation"),
                     ("dependency", "Dependency"),
                     ("fileaccess", "File access"),
                     ("skill", "Skill"),
                 })
        {
            categories.Add(new CategoryControls(key, label));
        }

        JsonObject? loaded = null;
        try
        {
            loaded = await client.GetSettingsAsync(cancellationToken).ConfigureAwait(true);
            Populate(loaded, mode, blockSeverity, discover, osv, report, categories, paths, ref originalReport);
            status.Text = $"Loaded from http://127.0.0.1:9700 at {DateTimeOffset.Now:HH:mm:ss}.";
        }
        catch (Exception exception) when (exception is
                     HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            status.Text = $"Blackbox settings are unavailable: {exception.Message}";
        }

        var add = Button("Add path", false);
        var remove = Button("Remove", false);
        var close = Button("Close", false);
        var save = Button("Save and verify", true);
        add.Click += (_, _) =>
        {
            var value = pathInput.Text?.Trim() ?? string.Empty;
            if (value.Length == 0 || paths.Contains(value, StringComparer.OrdinalIgnoreCase))
            {
                return;
            }

            if (paths.Count >= 100)
            {
                status.Text = "Blackbox allows at most 100 protected paths.";
                return;
            }

            paths.Add(value);
            pathInput.Text = string.Empty;
            status.Text = "Path added locally; save and verify to persist it.";
        };
        remove.Click += (_, _) =>
        {
            if (pathList.SelectedItem is string selected)
            {
                paths.Remove(selected);
                status.Text = "Path removed locally; save and verify to persist the change.";
            }
        };
        close.Click += (_, _) => window.Close();
        save.Click += async (_, _) =>
        {
            if (loaded is null)
            {
                status.Text = "Settings are not loaded; nothing was saved.";
                return;
            }

            var sharing = report.IsChecked == true;
            if (sharing && !originalReport)
            {
                var consent = await ui.ConfirmAsync(
                    "Enable threat sharing",
                    "Enable signed, redacted threat sharing with the community graph?\n\n" +
                    "This sends only signed, privacy-safe statements. It never sends prompts, commands, paths or credentials.",
                    "Enable sharing",
                    destructive: false,
                    CancellationToken.None).ConfigureAwait(true);
                if (!consent)
                {
                    status.Text = "Threat sharing was not enabled.";
                    return;
                }
            }

            var patch = new JsonObject
            {
                ["mode"] = mode.SelectedItem?.ToString() ?? "audit",
                ["block_severity"] = blockSeverity.SelectedItem?.ToString() ?? "critical",
                ["discover"] = discover.IsChecked == true,
                ["osv_lookup"] = osv.IsChecked == true,
                ["report"] = sharing,
                ["categories"] = new JsonObject(
                    categories.ToDictionary(
                        category => category.Key,
                        category => (JsonNode?)new JsonObject
                        {
                            ["enabled"] = category.Enabled.IsChecked == true,
                            ["min_severity"] = category.Severity.SelectedItem?.ToString() ?? "info",
                        })),
                ["protected_paths"] = new JsonArray(
                    paths.Select(path => (JsonNode?)JsonValue.Create(path)).ToArray()),
            };

            try
            {
                var result = await client.SaveSettingsAsync(patch, CancellationToken.None).ConfigureAwait(true);
                if (!result.Ok || result.Settings is null)
                {
                    status.Text = "Save failed: " + (result.Errors.Count == 0
                        ? "Blackbox rejected the update."
                        : string.Join("; ", result.Errors));
                    return;
                }

                var verification = Verify(result.Settings, mode, blockSeverity, paths);
                if (verification is not null)
                {
                    status.Text = $"Save verification failed: {verification}";
                    return;
                }

                loaded = result.Settings;
                originalReport = sharing;
                Populate(result.Settings, mode, blockSeverity, discover, osv, report, categories, paths, ref originalReport);
                status.Text = $"Saved and verified at {DateTimeOffset.Now:HH:mm:ss}.";
            }
            catch (Exception exception) when (exception is
                         HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
            {
                status.Text = $"Save failed: {exception.Message}";
            }
        };

        var rows = new StackPanel { Spacing = 6 };
        foreach (var category in categories)
        {
            var row = new Grid { ColumnDefinitions = new ColumnDefinitions("120,Auto,140") };
            row.Children.Add(new TextBlock { Text = category.Label, Foreground = Foreground, FontSize = 11, VerticalAlignment = VerticalAlignment.Center });
            category.Enabled.HorizontalAlignment = HorizontalAlignment.Left;
            Grid.SetColumn(category.Enabled, 1);
            row.Children.Add(category.Enabled);
            Grid.SetColumn(category.Severity, 2);
            row.Children.Add(category.Severity);
            rows.Children.Add(row);
        }
        var panel = new StackPanel { Spacing = 10, Margin = new Thickness(20) };
        panel.Children.Add(new SelectableTextBlock
        {
            Text = "Blackbox reads and writes only its local dashboard. Protected paths are stored by Blackbox, not Axiom.",
            Foreground = Muted,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
        });
        var settingsRow = new Grid { ColumnDefinitions = new ColumnDefinitions("140,140,Auto") };
        var modeField = Labeled("Mode", mode);
        var severityField = Labeled("Block severity", blockSeverity);
        var toggles = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 12,
            VerticalAlignment = VerticalAlignment.Bottom,
            Margin = new Thickness(20, 0, 0, 0),
            Children = { discover, osv, report },
        };
        settingsRow.Children.Add(modeField);
        Grid.SetColumn(severityField, 1);
        settingsRow.Children.Add(severityField);
        Grid.SetColumn(toggles, 2);
        settingsRow.Children.Add(toggles);
        panel.Children.Add(settingsRow);
        panel.Children.Add(new TextBlock { Text = "Protected paths", Foreground = Muted, FontSize = 10 });
        panel.Children.Add(pathList);
        var pathRow = new Grid { ColumnDefinitions = new ColumnDefinitions("*,8,Auto,6,Auto") };
        pathRow.Children.Add(pathInput);
        Grid.SetColumn(add, 2);
        pathRow.Children.Add(add);
        Grid.SetColumn(remove, 4);
        pathRow.Children.Add(remove);
        panel.Children.Add(pathRow);
        panel.Children.Add(new TextBlock { Text = "Categories", Foreground = Muted, FontSize = 10 });
        panel.Children.Add(rows);
        panel.Children.Add(status);
        panel.Children.Add(new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 8,
            Children = { close, save },
        });
        window.Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        await window.ShowDialog(owner).ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();
    }

    public async Task ShowLogAsync(string title, string text, CancellationToken cancellationToken)
    {
        var owner = ownerProvider();
        if (owner is null)
        {
            return;
        }

        var window = CreateWindow(title, 760);
        var close = Button("Close", false);
        close.Click += (_, _) => window.Close();
        window.Content = new Grid
        {
            RowDefinitions = new RowDefinitions("*,Auto"),
            Children =
            {
                new ScrollViewer
                {
                    Padding = new Thickness(16),
                    Content = new SelectableTextBlock
                    {
                        Text = text,
                        Foreground = Foreground,
                        FontFamily = new FontFamily("Consolas"),
                        FontSize = 11,
                        TextWrapping = TextWrapping.NoWrap,
                    },
                },
                new StackPanel
                {
                    HorizontalAlignment = HorizontalAlignment.Right,
                    Margin = new Thickness(16, 0, 16, 12),
                    Children = { close },
                },
            },
        };
        await window.ShowDialog(owner).ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();
    }

    private static string? Verify(
        JsonObject settings,
        ComboBox mode,
        ComboBox severity,
        ObservableCollection<string> paths)
    {
        if ((ReadString(settings, "mode") ?? "audit") != (mode.SelectedItem?.ToString() ?? "audit"))
        {
            return "mode did not persist.";
        }

        if ((ReadString(settings, "block_severity") ?? "critical") !=
            (severity.SelectedItem?.ToString() ?? "critical"))
        {
            return "block severity did not persist.";
        }

        var savedPaths = (settings["protected_paths"] as JsonArray)?
            .Select(node => node?.GetValue<string>() ?? string.Empty)
            .ToArray() ?? [];
        return savedPaths.SequenceEqual(paths, StringComparer.OrdinalIgnoreCase)
            ? null
            : "protected paths did not persist exactly.";
    }

    private static void Populate(
        JsonObject settings,
        ComboBox mode,
        ComboBox severity,
        CheckBox discover,
        CheckBox osv,
        CheckBox report,
        IReadOnlyList<CategoryControls> categories,
        ObservableCollection<string> paths,
        ref bool originalReport)
    {
        var severities = (settings["severity_order"] as JsonArray)?
            .Select(node => node?.GetValue<string>())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .ToArray() ?? Severities;

        mode.SelectedItem = ReadString(settings, "mode") ?? "audit";
        severity.ItemsSource = severities;
        severity.SelectedItem = ReadString(settings, "block_severity") ?? "critical";
        discover.IsChecked = ReadBool(settings, "discover", true);
        osv.IsChecked = ReadBool(settings, "osv_lookup", true);
        originalReport = ReadBool(settings, "report", false);
        report.IsChecked = originalReport;

        var categoryRoot = settings["categories"] as JsonObject;
        foreach (var category in categories)
        {
            var node = categoryRoot?[category.Key] as JsonObject;
            category.Enabled.IsChecked = node is null || ReadBool(node, "enabled", true);
            category.Severity.ItemsSource = severities;
            category.Severity.SelectedItem = ReadString(node, "min_severity") is { Length: > 0 } value
                ? value
                : "info";
        }

        paths.Clear();
        if (settings["protected_paths"] is JsonArray array)
        {
            foreach (var node in array)
            {
                if (node?.GetValue<string>() is { Length: > 0 } value && !paths.Contains(value))
                {
                    paths.Add(value);
                }
            }
        }
    }

    private static string? ReadString(JsonObject? obj, string key) =>
        obj?[key] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    private static bool ReadBool(JsonObject? obj, string key, bool fallback) =>
        obj?[key] is JsonValue value && value.TryGetValue<bool>(out var result) ? result : fallback;

    private static StackPanel Labeled(string label, Control control)
    {
        var panel = new StackPanel { Spacing = 4 };
        panel.Children.Add(new TextBlock { Text = label, Foreground = Muted, FontSize = 10 });
        panel.Children.Add(control);
        return panel;
    }

    private static Window CreateWindow(string title, int width) => new()
    {
        Title = title,
        Width = width,
        Height = 700,
        MinHeight = 320,
        WindowStartupLocation = WindowStartupLocation.CenterOwner,
        Background = Background,
        Foreground = Foreground,
    };

    private static Button Button(string label, bool primary)
    {
        var button = new Button
        {
            Content = label,
            MinWidth = 96,
            Padding = new Thickness(12, 6),
            CornerRadius = new CornerRadius(6),
        };
        if (primary)
        {
            button.Classes.Add("primary");
        }

        return button;
    }

    private sealed class CategoryControls(string key, string label)
    {
        public string Key { get; } = key;

        public string Label { get; } = label;

        public CheckBox Enabled { get; } = new()
        {
            Content = "Enabled",
            Foreground = Foreground,
            FontSize = 10,
        };

        public ComboBox Severity { get; } = new() { Width = 140 };
    }
}
