// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Windows;
using Microsoft.Win32;
using Axiom.Contracts.Blackbox;

namespace Axiom.UI.Views;

public partial class BlackboxSettingsWindow : Window
{
    private static readonly string[] DefaultSeverities = ["info", "low", "medium", "high", "critical"];

    private readonly BlackboxDashboardClient _client;

    private readonly ObservableCollection<string> _paths = [];

    private JsonObject? _settings;


    public BlackboxSettingsWindow(BlackboxDashboardClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        InitializeComponent();
        PathsList.ItemsSource = _paths;
        Loaded += async (_, _) => await LoadAsync().ConfigureAwait(true);
    }

    private async Task LoadAsync()
    {
        SetStatus("Loading settings…");
        SaveButton.IsEnabled = false;

        try
        {
            _settings = await _client.GetSettingsAsync(CancellationToken.None).ConfigureAwait(true);
            Populate(_settings);
            SaveButton.IsEnabled = true;
            SetStatus($"Loaded from http://127.0.0.1:9700 at {DateTimeOffset.Now:HH:mm:ss}.");
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            SaveButton.IsEnabled = false;
            SetStatus($"Blackbox settings are unavailable: {exception.Message} Use Open Dashboard for the web UI.");
        }
    }

    private void Populate(JsonObject settings)
    {
        var severities = (settings["severity_order"] as JsonArray)?
            .Select(node => node is JsonValue jv && jv.TryGetValue<string>(out var s) ? s : null)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .ToArray() ?? DefaultSeverities;

        ModeBox.ItemsSource = new[] { "audit", "block" };
        ModeBox.SelectedItem = ReadString(settings, "mode") ?? "audit";
        BlockSeverityBox.ItemsSource = severities;
        BlockSeverityBox.SelectedItem = ReadString(settings, "block_severity") ?? "critical";

        DiscoverCheck.IsChecked = ReadBool(settings, "discover", true);
        OsvCheck.IsChecked = ReadBool(settings, "osv_lookup", true);
        ReportCheck.IsChecked = false;

        var categories = settings["categories"] as JsonObject;
        PopulateCategory(categories, "injection", InjectionCheck, InjectionSeverity, severities);
        PopulateCategory(categories, "escalation", EscalationCheck, EscalationSeverity, severities);
        PopulateCategory(categories, "dependency", DependencyCheck, DependencySeverity, severities);
        PopulateCategory(categories, "fileaccess", FileAccessCheck, FileAccessSeverity, severities);
        PopulateCategory(categories, "skill", SkillCheck, SkillSeverity, severities);

        _paths.Clear();
        if (settings["protected_paths"] is JsonArray paths)
        {
            foreach (var path in paths)
            {
                if (path is JsonValue jv && jv.TryGetValue<string>(out var value) &&
                    value.Length > 0 && !_paths.Contains(value))
                {
                    _paths.Add(value);
                }
            }
        }

        var traderEnabled = ((settings["shields"] as JsonObject)?["trader"] as JsonObject)?
            ["mode"] is JsonObject mode && ReadBool(mode, "enabled", false);
        TraderShieldText.Text = traderEnabled == true
            ? "Trader Shield is enabled. Editing wallet and address settings stays in the Blackbox dashboard until its schema and consent flow are confirmed here."
            : "Trader Shield is disabled. It remains read-only on this page.";
    }

    private static void PopulateCategory(
        JsonObject? categories,
        string key,
        System.Windows.Controls.CheckBox check,
        System.Windows.Controls.ComboBox severity,
        IReadOnlyList<string> severities)
    {
        var category = categories?[key] as JsonObject;
        check.IsChecked = category is null || ReadBool(category, "enabled", true);
        severity.ItemsSource = severities;
        severity.SelectedItem = ReadString(category, "min_severity") is { Length: > 0 } value
            ? value
            : "info";
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        if (_settings is null)
        {
            SetStatus("Settings are not loaded; nothing was saved.");
            return;
        }

        var patch = new JsonObject
        {
            ["mode"] = ModeBox.SelectedItem?.ToString() ?? "audit",
            ["block_severity"] = BlockSeverityBox.SelectedItem?.ToString() ?? "critical",
            ["discover"] = DiscoverCheck.IsChecked == true,
            ["osv_lookup"] = OsvCheck.IsChecked == true,
            ["categories"] = new JsonObject
            {
                ["injection"] = CategoryPatch(InjectionCheck, InjectionSeverity),
                ["escalation"] = CategoryPatch(EscalationCheck, EscalationSeverity),
                ["dependency"] = CategoryPatch(DependencyCheck, DependencySeverity),
                ["fileaccess"] = CategoryPatch(FileAccessCheck, FileAccessSeverity),
                ["skill"] = CategoryPatch(SkillCheck, SkillSeverity),
            },
            ["protected_paths"] = new JsonArray(
                _paths.Select(path => (JsonNode?)JsonValue.Create(path)).ToArray()),
        };

        if (ReportCheck.IsChecked == true)
        {
            patch["report"] = false;
        }

        SaveButton.IsEnabled = false;
        SetStatus("Saving…");

        try
        {
            var result = await _client.SaveSettingsAsync(patch, CancellationToken.None).ConfigureAwait(true);
            if (!result.Ok || result.Settings is null)
            {
                SetStatus("Save failed: " + (result.Errors.Count == 0
                    ? "Blackbox rejected the update."
                    : string.Join("; ", result.Errors)));
                return;
            }

            var verification = Verify(result.Settings);
            if (verification is not null)
            {
                SetStatus($"Save verification failed: {verification}");
                return;
            }

            _settings = result.Settings;
            Populate(result.Settings);
            SetStatus($"Saved and verified at {DateTimeOffset.Now:HH:mm:ss}.");
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            SetStatus($"Save failed: {exception.Message}");
        }
        finally
        {
            SaveButton.IsEnabled = true;
        }
    }

    private string? Verify(JsonObject settings)
    {
        if ((ReadString(settings, "mode") ?? "audit") != (ModeBox.SelectedItem?.ToString() ?? "audit"))
        {
            return "mode did not persist.";
        }

        if ((ReadString(settings, "block_severity") ?? "critical") !=
            (BlockSeverityBox.SelectedItem?.ToString() ?? "critical"))
        {
            return "block severity did not persist.";
        }

        var savedPaths = (settings["protected_paths"] as JsonArray)?
            .Select(node => node is JsonValue jv && jv.TryGetValue<string>(out var s) ? s : string.Empty)
            .ToArray() ?? [];
        if (!savedPaths.SequenceEqual(_paths, StringComparer.OrdinalIgnoreCase))
        {
            return "protected paths did not persist exactly.";
        }

        return null;
    }

    private static JsonObject CategoryPatch(
        System.Windows.Controls.CheckBox check,
        System.Windows.Controls.ComboBox severity) => new()
    {
        ["enabled"] = check.IsChecked == true,
        ["min_severity"] = severity.SelectedItem?.ToString() ?? "info",
    };

    private void AddPattern_Click(object sender, RoutedEventArgs e)
    {
        AddPath(PathBox.Text);
        PathBox.Clear();
    }

    private void AddFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Protect a file",
            CheckFileExists = true,
        };

        if (dialog.ShowDialog(this) == true)
        {
            AddPath(dialog.FileName);
        }
    }

    private void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "Protect a folder",
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) == true)
        {
            AddPath(dialog.FolderName);
        }
    }

    private void AddPath(string? value)
    {
        var path = value?.Trim() ?? string.Empty;
        if (path.Length == 0)
        {
            return;
        }

        if (_paths.Count >= 100)
        {
            SetStatus("Blackbox allows at most 100 protected paths.");
            return;
        }

        if (_paths.Contains(path, StringComparer.OrdinalIgnoreCase))
        {
            SetStatus("That path is already protected.");
            return;
        }

        _paths.Add(path);
        PathsList.SelectedItem = path;
        SetStatus("Path added locally; Save and verify to persist it.");
    }

    private void RemovePath_Click(object sender, RoutedEventArgs e)
    {
        if (PathsList.SelectedItem is not string path)
        {
            return;
        }

        var confirmation = MessageBox.Show(
            $"Remove this protected path?\n\n{path}",
            "Remove protected path",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirmation == MessageBoxResult.Yes)
        {
            _paths.Remove(path);
            SetStatus("Path removed locally; Save and verify to persist the change.");
        }
    }

    private async void Reload_Click(object sender, RoutedEventArgs e) => await LoadAsync().ConfigureAwait(true);

    private void OpenDashboard_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            using var _ = Process.Start(new ProcessStartInfo("http://127.0.0.1:9700")
            {
                UseShellExecute = true,
            });
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            SetStatus($"Could not open the dashboard: {exception.Message}");
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => Close();

    private void SetStatus(string text) => StatusText.Text = text;

    private static string? ReadString(JsonObject? element, string propertyName) =>
        element?[propertyName] is JsonValue value && value.TryGetValue<string>(out var text)
            ? text
            : null;

    private static bool ReadBool(JsonObject? element, string propertyName, bool fallback) =>
        element?[propertyName] is JsonValue value && value.TryGetValue<bool>(out var result)
            ? result
            : fallback;
}
