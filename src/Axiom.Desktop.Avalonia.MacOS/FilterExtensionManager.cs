// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.MacOS;

/// <summary>One <c>axiom-sysext</c> answer (macos/README.md: one JSON object on stdout).</summary>
public sealed record FilterExtensionStatus(
    string Command,
    int ExitCode,
    bool Ok,
    string State,
    string? Message,
    bool FilterConfigured,
    bool FilterEnabled)
{
    public const string ApprovalPath =
        "System Settings > General > Login Items & Extensions > Network Extensions";

    public bool IsRunning => string.Equals(State, "running", StringComparison.Ordinal) ||
                             (string.Equals(State, "activated", StringComparison.Ordinal) && FilterEnabled) ||
                             (string.Equals(State, "enabled", StringComparison.Ordinal) && FilterEnabled);

    public bool NeedsApproval => ExitCode == 3 || string.Equals(State, "needs_approval", StringComparison.Ordinal);

    public bool NeedsReboot => ExitCode == 4 || string.Equals(State, "reboot_required", StringComparison.Ordinal);

    /// <summary>A short, user-facing sentence for the menu and dialogs.</summary>
    public string Summary => State switch
    {
        _ when NeedsReboot => "Restart the Mac to finish installing the Axiom network filter.",
        _ when NeedsApproval =>
            "The Axiom network filter is waiting for your approval in " + ApprovalPath +
            ". Turn on Axiom, enter your password, then allow \"Filter Network Content\".",
        "running" or "activated" or "enabled" when FilterEnabled => "The Axiom network filter is running.",
        "installed_filter_disabled" or "disabled" =>
            "The Axiom network filter is installed but turned off.",
        "not_installed" => "The Axiom network filter is not installed.",
        "unavailable" => Message ?? "The Axiom network filter helper is not available.",
        "timeout" => "macOS did not answer in time. Try again.",
        _ => Message ?? (Ok ? $"Network filter state: {State}." : $"Network filter error ({State})."),
    };

    public static FilterExtensionStatus Unavailable(string command, string message) =>
        new(command, 1, false, "unavailable", message, false, false);

    /// <summary>Parses the helper's stdout. Unknown or broken output becomes an error state.</summary>
    public static FilterExtensionStatus Parse(string command, int exitCode, string standardOutput)
    {
        var text = standardOutput?.Trim() ?? string.Empty;
        var start = text.IndexOf('{', StringComparison.Ordinal);
        var end = text.LastIndexOf('}');
        if (start < 0 || end <= start)
        {
            return new FilterExtensionStatus(command, exitCode, false, "error", "axiom-sysext printed no status.", false, false);
        }

        try
        {
            using var document = JsonDocument.Parse(text[start..(end + 1)]);
            var root = document.RootElement;
            var state = String(root, "state") ?? (exitCode == 0 ? "ok" : "error");
            var message = String(root, "message");
            if (message is null &&
                root.TryGetProperty("error", out var error) &&
                error.ValueKind == JsonValueKind.Object)
            {
                message = String(error, "message");
            }

            var configured = false;
            var enabled = false;
            if (root.TryGetProperty("filter", out var filter) && filter.ValueKind == JsonValueKind.Object)
            {
                configured = Bool(filter, "configured");
                enabled = Bool(filter, "enabled");
            }

            var ok = root.TryGetProperty("ok", out var okElement)
                ? okElement.ValueKind == JsonValueKind.True
                : exitCode == 0;
            return new FilterExtensionStatus(command, exitCode, ok, state, message, configured, enabled);
        }
        catch (JsonException)
        {
            return new FilterExtensionStatus(command, exitCode, false, "error", "axiom-sysext printed invalid JSON.", false, false);
        }
    }

    private static string? String(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool Bool(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;
}

/// <summary>
/// Runs the bundled <c>Contents/MacOS/axiom-sysext</c> helper (activate | enable | status …). The
/// helper must run from inside Axiom.app; outside a bundle the manager reports "unavailable".
/// </summary>
public sealed class FilterExtensionManager(MacBundleLayout layout)
{
    public FilterExtensionManager()
        : this(MacBundleLayout.Current)
    {
    }

    public bool IsAvailable => OperatingSystem.IsMacOS() && layout.IsInsideAppBundle && File.Exists(layout.SysextHelperPath);

    public Task<FilterExtensionStatus> StatusAsync(CancellationToken cancellationToken) =>
        RunAsync("status", ["--timeout", "15"], TimeSpan.FromSeconds(25), cancellationToken);

    /// <summary>Installs/approves the extension and turns the filter on; waits for the user up to 120 s.</summary>
    public Task<FilterExtensionStatus> ActivateAsync(CancellationToken cancellationToken) =>
        RunAsync("activate", ["--timeout", "120"], TimeSpan.FromSeconds(150), cancellationToken);

    public Task<FilterExtensionStatus> EnableAsync(CancellationToken cancellationToken) =>
        RunAsync("enable", [], TimeSpan.FromSeconds(60), cancellationToken);

    private async Task<FilterExtensionStatus> RunAsync(
        string command,
        string[] arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsMacOS())
        {
            return FilterExtensionStatus.Unavailable(command, "The network filter exists only on macOS.");
        }

        if (!layout.IsInsideAppBundle || !File.Exists(layout.SysextHelperPath))
        {
            return FilterExtensionStatus.Unavailable(
                command,
                "This Axiom build has no network filter (axiom-sysext is missing from Axiom.app).");
        }

        if (!layout.IsInApplicationsFolder && !string.Equals(command, "status", StringComparison.Ordinal))
        {
            return FilterExtensionStatus.Unavailable(
                command,
                "Move Axiom.app to /Applications first: macOS only activates network filters from there.");
        }

        var startInfo = new ProcessStartInfo(layout.SysextHelperPath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add(command);
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return FilterExtensionStatus.Unavailable(command, "axiom-sysext did not start.");
            }

            var output = process.StandardOutput.ReadToEndAsync(timeoutSource.Token);
            var error = process.StandardError.ReadToEndAsync(timeoutSource.Token);
            try
            {
                await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                process.Kill();
                return new FilterExtensionStatus(command, 2, false, "timeout", null, false, false);
            }

            var stdout = await output.ConfigureAwait(false);
            var stderr = await error.ConfigureAwait(false);
            var status = FilterExtensionStatus.Parse(command, process.ExitCode, stdout);
            StartupLog.Write(
                "sysext",
                $"{command} exit={process.ExitCode} state={status.State} enabled={status.FilterEnabled}" +
                (status.Ok ? string.Empty : " stderr=" + Tail(stderr)));
            return status;
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or IOException)
        {
            return FilterExtensionStatus.Unavailable(command, "axiom-sysext could not run: " + exception.Message);
        }
    }

    private static string Tail(string text)
    {
        var trimmed = text.Trim().ReplaceLineEndings(" | ");
        return trimmed.Length <= 400 ? trimmed : trimmed[^400..];
    }
}
