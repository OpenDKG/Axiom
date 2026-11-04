// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Netpetra.Contracts.Blackbox;
using Netpetra.UI.Views;

namespace Netpetra.UI.ViewModels;

/// <summary>
/// Agent protection page. It owns the focused Blackbox control-center reads (settings, health,
/// audit) and keeps the existing SecurityViewModel probe/timer for module installation state.
/// Polling is active only while this page is selected.
/// </summary>
public sealed partial class AgentsViewModel : PageViewModel, IActivatablePage, IDisposable
{
    private readonly BlackboxDashboardClient _client = new();

    private readonly DispatcherTimer _timer;

    private readonly List<BlackboxAuditEntry> _allActivity = [];

    private readonly List<BlackboxFinding> _allFindings = [];

    private bool _refreshing;

    public AgentsViewModel(SecurityViewModel security)
        : base("Agents", "DKG, Blackbox and the workspaces they protect", "\uE99A")
    {
        Security = security ?? throw new ArgumentNullException(nameof(security));

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
        _timer.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(true);
    }

    public SecurityViewModel Security { get; }

    public IReadOnlyList<string> ActivityFilters { get; } = ["All Activity", "Threats", "Blocked"];

    public IReadOnlyList<string> AgentFilters { get; } =
        ["All agents", "Hermes", "OpenClaw", "OpenCode", "OpenChamber", "Codex", "Unknown"];

    public IReadOnlyList<string> SeverityFilters { get; } =
        ["All severities", "Info", "Low", "Medium", "High", "Critical"];

    public ObservableCollection<BlackboxAuditEntry> Activity { get; } = [];

    public ObservableCollection<BlackboxFinding> Findings { get; } = [];

    [ObservableProperty]
    private string _selectedActivityFilter = "All Activity";

    [ObservableProperty]
    private string _selectedAgentFilter = "All agents";

    [ObservableProperty]
    private string _selectedSeverityFilter = "All severities";

    [ObservableProperty]
    private string _activityStatusText = "Select the Agents page to load local Blackbox activity.";

    [ObservableProperty]
    private string _healthStatusText = "Blackbox health is not loaded yet.";

    [ObservableProperty]
    private string _blackboxHealthText = "Dashboard: unknown";

    [ObservableProperty]
    private string _dkgHealthText = "DKG: unknown";

    [ObservableProperty]
    private string _netpetraDkgHealthText = "Netpetra DKG: unknown";

    [ObservableProperty]
    private string _graphHealthText = "Verified graph: unknown";

    [ObservableProperty]
    private string _summaryText = "No activity has been loaded.";

    [ObservableProperty]
    private string _lastBlockedText = "No blocked action observed.";

    [ObservableProperty]
    private string _protectedPathViolationsText = "0 protected-path findings";

    [ObservableProperty]
    private string _unresolvedText = "0 unresolved findings";

    [ObservableProperty]
    private string _protectionTestText = "Protection test has not run.";

    public void Activate()
    {
        _timer.Start();
        _ = RefreshAsync();
    }

    public void Deactivate() => _timer.Stop();

    public void Dispose()
    {
        _timer.Stop();
        _client.Dispose();
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        if (_refreshing)
        {
            return;
        }

        _refreshing = true;
        try
        {
            var settingsTask = _client.GetSettingsAsync(CancellationToken.None);
            var graphTask = _client.GetGraphStatusAsync(CancellationToken.None);
            var auditTask = _client.GetAuditAsync(100, 0, CancellationToken.None);
            var findingsTask = _client.GetFindingsAsync(100, 0, CancellationToken.None);

            await Task.WhenAll(settingsTask, graphTask, auditTask, findingsTask).ConfigureAwait(true);

            ApplyActivity(auditTask.Result);
            ApplyFindings(findingsTask.Result);
            ApplyHealth(settingsTask.Result, graphTask.Result);
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            ActivityStatusText = $"Blackbox is unavailable: {exception.Message}";
            HealthStatusText = "Blackbox dashboard is offline or not responding.";
            SummaryText = "No live Blackbox data is available.";
        }
        finally
        {
            _refreshing = false;
        }
    }

    [RelayCommand]
    private async Task RefreshAllAsync()
    {
        await Security.RefreshCommand.ExecuteAsync(null).ConfigureAwait(true);
        await RefreshAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task TestProtectionAsync()
    {
        var confirmation = MessageBox.Show(
            "Run a harmless protected-file canary test?\n\n" +
            "Netpetra creates a temporary file, adds it to Blackbox protected paths, calls the local " +
            "Blackbox guard, then removes the temporary file and restores the original paths. " +
            "No credentials, wallet files or destructive command are used.",
            "Test Blackbox protection",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirmation != MessageBoxResult.Yes)
        {
            return;
        }

        ProtectionTestText = "Testing…";
        try
        {
            var settings = await _client.GetSettingsAsync(CancellationToken.None).ConfigureAwait(true);
            if (!string.Equals(ReadString(settings, "mode"), "block", StringComparison.OrdinalIgnoreCase))
            {
                ProtectionTestText = "INCONCLUSIVE — Blackbox is in audit mode. Switch to Block, then retry.";
                return;
            }

            var originalPaths = (settings["protected_paths"] as JsonArray)?
                .Select(node => node?.GetValue<string>() ?? string.Empty)
                .Where(path => path.Length > 0)
                .ToArray() ?? [];

            var canary = Path.Combine(
                Path.GetTempPath(),
                $"netpetra-protection-test-{Guid.NewGuid():N}.txt");
            await File.WriteAllTextAsync(canary, "NETPETRA SECURITY TEST").ConfigureAwait(true);

            try
            {
                var withCanary = new JsonArray(
                    originalPaths.Select(path => (JsonNode?)JsonValue.Create(path))
                        .Append(JsonValue.Create(canary))
                        .ToArray());
                var save = await _client.SaveSettingsAsync(
                    new JsonObject { ["protected_paths"] = withCanary },
                    CancellationToken.None).ConfigureAwait(true);
                if (!save.Ok)
                {
                    ProtectionTestText = "FAIL — could not add the canary to protected paths: " +
                        string.Join("; ", save.Errors);
                    return;
                }

                var decision = await RunGuardAsync(canary).ConfigureAwait(true);
                var action = ReadString(decision, "action");
                var message = ReadString(decision, "message");
                ProtectionTestText = string.Equals(action, "block", StringComparison.OrdinalIgnoreCase)
                    ? "PASS (guard-level) — Blackbox rejected the canary read. Agent hook execution was not exercised."
                    : $"FAIL/INCONCLUSIVE — the guard did not block the canary read. {message}".Trim();
            }
            finally
            {
                var cleanupError = await RemoveCanaryPathAsync(canary).ConfigureAwait(true);
                File.Delete(canary);
                if (cleanupError is not null)
                {
                    ProtectionTestText += $" Cleanup issue: {cleanupError}";
                }
            }
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or
            System.Text.Json.JsonException or IOException or InvalidOperationException or
            TimeoutException or System.ComponentModel.Win32Exception)
        {
            ProtectionTestText = $"INCONCLUSIVE — {exception.Message}";
        }
        finally
        {
            await RefreshAsync().ConfigureAwait(true);
        }
    }

    private async Task<string?> RemoveCanaryPathAsync(string canary)
    {
        try
        {
            // Re-read immediately before cleanup so a concurrent user edit is preserved.
            var current = await _client.GetSettingsAsync(CancellationToken.None).ConfigureAwait(true);
            var currentPaths = (current["protected_paths"] as JsonArray)?
                .Select(node => node?.GetValue<string>() ?? string.Empty)
                .Where(path => path.Length > 0)
                .ToArray() ?? [];

            var remaining = currentPaths
                .Where(path => !string.Equals(path, canary, StringComparison.OrdinalIgnoreCase))
                .ToArray();

            if (remaining.Length == currentPaths.Length)
            {
                return null;
            }

            var patch = new JsonObject
            {
                ["protected_paths"] = new JsonArray(
                    remaining.Select(path => (JsonNode?)JsonValue.Create(path)).ToArray()),
            };
            var result = await _client.SaveSettingsAsync(patch, CancellationToken.None).ConfigureAwait(true);
            return result.Ok ? null : string.Join("; ", result.Errors);
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            return $"could not remove the canary path: {exception.Message}";
        }
    }

    private async Task<JsonObject?> RunGuardAsync(string path)
    {
        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Netpetra",
            "modules",
            "blackbox",
            "agent-blackbox");
        var python = Path.Combine(root, "venv", "Scripts", "python.exe");
        var bridge = Path.Combine(root, "netpetra-guard-bridge.py");
        if (!File.Exists(python) || !File.Exists(bridge))
        {
            throw new InvalidOperationException("Blackbox guard bridge is not installed.");
        }

        var startInfo = new ProcessStartInfo(python)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = root,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add(bridge);

        using var process = Process.Start(startInfo) ??
                            throw new InvalidOperationException("Could not start the Blackbox guard bridge.");
        await process.StandardInput.WriteAsync(new JsonObject
        {
            ["tool"] = "read",
            ["args"] = new JsonObject { ["path"] = path },
            ["session"] = "netpetra-protection-test",
            ["call"] = Guid.NewGuid().ToString("N"),
        }.ToJsonString()).ConfigureAwait(true);
        process.StandardInput.Close();

        var output = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(true);
        if (!process.WaitForExit(15000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Blackbox guard timed out.");
        }

        return JsonNode.Parse(output) as JsonObject;
    }

    [RelayCommand]
    private async Task SetBlackboxModeAsync(string? mode)
    {
        if (mode is not ("audit" or "block"))
        {
            return;
        }

        try
        {
            var result = await _client.SaveSettingsAsync(
                new JsonObject { ["mode"] = mode },
                CancellationToken.None).ConfigureAwait(true);

            if (!result.Ok || result.Settings is null)
            {
                HealthStatusText = "Mode change failed: " + (result.Errors.Count == 0
                    ? "Blackbox rejected the update."
                    : string.Join("; ", result.Errors));
                return;
            }

            var savedMode = ReadString(result.Settings, "mode");
            if (!string.Equals(savedMode, mode, StringComparison.OrdinalIgnoreCase))
            {
                HealthStatusText = "Mode verification failed: Blackbox did not persist the requested mode.";
                return;
            }

            HealthStatusText = $"Mode changed to {mode} and verified at {DateTimeOffset.Now:HH:mm:ss}.";
            await Security.RefreshCommand.ExecuteAsync(null).ConfigureAwait(true);
            await RefreshAsync().ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is
            HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            HealthStatusText = $"Mode change failed: {exception.Message}";
        }
    }

    [RelayCommand]
    private async Task ConfigureAsync()
    {
        var window = new BlackboxSettingsWindow(_client)
        {
            Owner = Application.Current?.MainWindow,
        };
        window.ShowDialog();
        await RefreshAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    private void ViewDkgLog()
    {
        var candidates = new[]
        {
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Netpetra",
                "modules",
                "dkg-home",
                "daemon.log"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "hermes",
                "blackbox",
                "dkg",
                "daemon.log"),
        };

        var path = candidates.FirstOrDefault(File.Exists);
        var text = path is null
            ? "No DKG daemon.log was found at:\n" + string.Join("\n", candidates)
            : ReadBoundedLog(path);

        var window = new DkgLogWindow(text)
        {
            Owner = Application.Current?.MainWindow,
        };
        window.ShowDialog();
    }

    private static string ReadBoundedLog(string path)
    {
        try
        {
            var lines = File.ReadLines(path).TakeLast(200).ToArray();
            var text = string.Join('\n', lines);
            if (text.Length > 64 * 1024)
            {
                text = text[^Math.Min(text.Length, 64 * 1024)..];
            }

            text = Regex.Replace(
                text,
                @"(?i)(token|secret|password|api[_-]?key)\s*[:=]\s*\S+",
                "$1=[redacted]");
            return Regex.Replace(text, @"[A-Fa-f0-9]{32,}", "[redacted-hex]");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return $"Could not read {path}: {exception.Message}";
        }
    }

    [RelayCommand]
    private void OpenDashboard()
    {
        try
        {
            Process.Start(new ProcessStartInfo("http://127.0.0.1:9700") { UseShellExecute = true });
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            ActivityStatusText = $"Could not open the Blackbox dashboard: {exception.Message}";
        }
    }

    [RelayCommand]
    private void SetActivityFilter(string? filter)
    {
        SelectedActivityFilter = filter ?? "All Activity";
        ApplyFilters();
    }

    [RelayCommand]
    private void SetAgentFilter(string? filter)
    {
        SelectedAgentFilter = filter ?? "All agents";
        ApplyFilters();
    }

    [RelayCommand]
    private void SetSeverityFilter(string? filter)
    {
        SelectedSeverityFilter = filter ?? "All severities";
        ApplyFilters();
    }

    partial void OnSelectedActivityFilterChanged(string value) => ApplyFilters();

    partial void OnSelectedAgentFilterChanged(string value) => ApplyFilters();

    partial void OnSelectedSeverityFilterChanged(string value) => ApplyFilters();

    private void ApplyActivity(BlackboxAuditPage page)
    {
        _allActivity.Clear();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in page.Entries)
        {
            var key = string.Join(
                '|',
                entry.Timestamp?.ToUnixTimeSeconds(),
                entry.Event,
                entry.Agent,
                entry.Session,
                entry.Tool,
                entry.Identifier,
                entry.Decision);
            if (seen.Add(key))
            {
                _allActivity.Add(entry);
            }
        }

        ActivityStatusText = $"{page.Total} audit event(s); showing the newest {_allActivity.Count}.";
        ApplyFilters();
    }

    private void ApplyFindings(BlackboxFindingPage page)
    {
        _allFindings.Clear();
        _allFindings.AddRange(page.Findings);

        var blocked = _allFindings.Count(finding => finding.IsBlocked);
        var flagged = _allFindings.Count(finding => finding.IsFlagged);
        var fileAccess = _allFindings.Count(finding =>
            string.Equals(finding.Category, "fileaccess", StringComparison.OrdinalIgnoreCase));
        var unresolved = _allFindings.Count(finding => !finding.IsBlocked);

        ProtectedPathViolationsText = $"{fileAccess} protected-path finding(s)";
        UnresolvedText = $"{unresolved} unresolved or unverified finding(s)";
        SummaryText = $"{_allFindings.Count} finding(s): {blocked} blocked, {flagged} flagged.";

        var lastBlocked = _allFindings
            .Where(finding => finding.IsBlocked)
            .OrderByDescending(finding => finding.Timestamp)
            .FirstOrDefault();
        LastBlockedText = lastBlocked is null
            ? "No blocked action observed."
            : $"{lastBlocked.TimeText} · {lastBlocked.Agent} · {lastBlocked.Tool} · {lastBlocked.Identifier}";
    }

    private void ApplyHealth(JsonObject settings, JsonObject graph)
    {
        var mode = ReadString(settings, "mode") ?? "unknown";
        var report = ReadBool(settings, "report", false);
        BlackboxHealthText = $"Dashboard online · mode {mode} · community sharing {(report ? "ON" : "off")}";

        var dkgUrl = ReadString(graph, "dkg_url") ?? "unknown";
        var reachable = ReadBool(graph, "node_reachable", false);
        DkgHealthText = $"Blackbox DKG: {dkgUrl} · {(reachable ? "reachable" : "offline")}";

        var dkgModule = Security.Modules.FirstOrDefault(module => module.Name == "OriginTrail DKG");
        NetpetraDkgHealthText = dkgModule is null
            ? "Netpetra DKG: unknown"
            : $"Netpetra DKG: {dkgModule.Status} · {dkgModule.Detail}";

        var ruleset = graph["ruleset"] as JsonObject;
        var verified = ReadInt(ruleset, "injection") + ReadInt(ruleset, "escalation") +
                       ReadInt(ruleset, "dependency") + ReadInt(ruleset, "fileaccess") +
                       ReadInt(ruleset, "skill") + ReadInt(ruleset, "ioc");
        var community = ReadInt(graph, "community");
        GraphHealthText = $"Verified graph: {verified} rule(s) · community: {community}";

        var lastSync = ReadString(graph, "last_sync");
        HealthStatusText = reachable
            ? $"Blackbox dashboard and DKG are reachable. Last sync: {lastSync ?? "not reported"}."
            : "Dashboard is online, but its configured DKG node is offline. Local rules may still protect; verified graph coverage is not synchronized.";
    }

    private void ApplyFilters()
    {
        Activity.Clear();
        var severityFilter = SelectedSeverityFilter == "All severities"
            ? null
            : SelectedSeverityFilter.ToLowerInvariant();

        foreach (var entry in _allActivity)
        {
            if (SelectedActivityFilter == "Threats" && !entry.IsThreat)
            {
                continue;
            }

            if (SelectedActivityFilter == "Blocked" && !entry.IsBlocked)
            {
                continue;
            }

            if (SelectedAgentFilter != "All agents" &&
                !string.Equals(entry.Agent, SelectedAgentFilter, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (severityFilter is not null &&
                !string.Equals(entry.Severity, severityFilter, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            Activity.Add(entry);
        }
    }

    private static string? ReadString(JsonObject? element, string propertyName) =>
        element?[propertyName] is JsonValue value && value.TryGetValue<string>(out var text)
            ? text
            : null;

    private static bool ReadBool(JsonObject? element, string propertyName, bool fallback) =>
        element?[propertyName] is JsonValue value && value.TryGetValue<bool>(out var result)
            ? result
            : fallback;

    private static int ReadInt(JsonObject? element, string propertyName) =>
        element?[propertyName] is JsonValue value && value.TryGetValue<int>(out var result)
            ? result
            : 0;
}
