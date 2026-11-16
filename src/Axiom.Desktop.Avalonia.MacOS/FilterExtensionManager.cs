// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text.Json;
using Axiom.Contracts;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.MacOS;

/// <summary>One activation-host answer (macos/README.md: one JSON object on stdout).</summary>
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

    /// <summary>The name macOS shows for the requesting app in System Settings.</summary>
    public const string HostDisplayName = "Axiom Network Filter";

    public const int ExitOk = 0;

    public const int ExitError = 1;

    public const int ExitTimeout = 2;

    public const int ExitNeedsApproval = 3;

    public const int ExitRebootRequired = 4;

    public bool IsRunning => string.Equals(State, "running", StringComparison.Ordinal) ||
                             (string.Equals(State, "activated", StringComparison.Ordinal) && FilterEnabled) ||
                             (string.Equals(State, "enabled", StringComparison.Ordinal) && FilterEnabled);

    public bool NeedsApproval => ExitCode == ExitNeedsApproval || string.Equals(State, "needs_approval", StringComparison.Ordinal);

    public bool NeedsReboot => ExitCode == ExitRebootRequired || string.Equals(State, "reboot_required", StringComparison.Ordinal);

    /// <summary>A short, user-facing sentence for the menu and dialogs.</summary>
    public string Summary => State switch
    {
        _ when NeedsReboot => "Restart the Mac to finish installing the Axiom network filter.",
        _ when NeedsApproval =>
            "The Axiom network filter is waiting for your approval in " + ApprovalPath +
            ". Turn on " + HostDisplayName + ", enter your password, then allow \"Filter Network Content\".",
        "running" or "activated" or "enabled" when FilterEnabled => "The Axiom network filter is running.",
        "installed_filter_disabled" or "disabled" =>
            "The Axiom network filter is installed but turned off.",
        "not_installed" => "The Axiom network filter is not installed.",
        "unavailable" => Message ?? "The Axiom network filter is unavailable.",
        "timeout" => "macOS did not answer in time. Try again.",
        _ => Message ?? (Ok ? $"Network filter state: {State}." : $"Network filter error ({State})."),
    };

    public static FilterExtensionStatus Unavailable(string command, string message) =>
        new(command, ExitError, false, "unavailable", message, false, false);

    /// <summary>Parses the host's stdout. Unknown or broken output becomes an error state.</summary>
    public static FilterExtensionStatus Parse(string command, int exitCode, string standardOutput)
    {
        var text = standardOutput?.Trim() ?? string.Empty;
        var start = text.IndexOf('{', StringComparison.Ordinal);
        var end = text.LastIndexOf('}');
        if (start < 0 || end <= start)
        {
            return new FilterExtensionStatus(command, exitCode, false, "error", "The activation host printed no status.", false, false);
        }

        try
        {
            using var document = JsonDocument.Parse(text[start..(end + 1)]);
            var root = document.RootElement;
            var state = String(root, "state") ?? (exitCode == ExitOk ? "ok" : "error");
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
                : exitCode == ExitOk;
            return new FilterExtensionStatus(command, exitCode, ok, state, message, configured, enabled);
        }
        catch (JsonException)
        {
            return new FilterExtensionStatus(command, exitCode, false, "error", "The activation host printed invalid JSON.", false, false);
        }
    }

    private static string? String(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool Bool(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;
}

/// <summary>Which activation path <see cref="FilterExtensionManager"/> used for its last call.</summary>
public enum FilterExtensionPath
{
    None,

    /// <summary>The signed <c>AxiomFilterHost.app/Contents/MacOS/axiom-sysext</c> child process.</summary>
    Host,
}

/// <summary>Runs the activation host; replaced in tests.</summary>
public delegate Task<ToolProcessResult> SysextHostRunner(
    string path,
    string[] arguments,
    TimeSpan timeout,
    CancellationToken cancellationToken);

/// <summary>Facts about the host that decide whether and how the filter can be managed.</summary>
public sealed record FilterExtensionEnvironment(
    bool IsMacOS,
    bool IsInsideAppBundle,
    bool HostInApplicationsFolder,
    string HostPath,
    bool HostPresent)
{
    public static FilterExtensionEnvironment Probe(MacBundleLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        return new FilterExtensionEnvironment(
            OperatingSystem.IsMacOS(),
            layout.IsInsideAppBundle,
            layout.IsSysextHostInApplicationsFolder,
            layout.SysextHostExecutablePath,
            File.Exists(layout.SysextHostExecutablePath));
    }
}

/// <summary>
/// Manages the AxiomFilter system extension (activate | deactivate | enable | status …) through the
/// separately signed <c>AxiomFilterHost.app</c>. The host is the app that owns the extension: it is
/// in /Applications, carries the restricted entitlements and its own provisioning profile, and
/// submits <c>OSSystemExtensionRequest</c> from its own main bundle. The Avalonia/.NET JIT process
/// never claims those entitlements and only runs the host with a fixed argument list; the contract
/// is the same single JSON object and exit code the Swift CLI always used.
/// </summary>
public sealed class FilterExtensionManager
{
    private const int StatusTimeoutSeconds = 15;

    private const int ActivateTimeoutSeconds = 120;

    private const int EnableTimeoutSeconds = 60;

    private readonly Func<FilterExtensionEnvironment> _environment;

    private readonly SysextHostRunner _host;

    private readonly Action<string> _log;

    public FilterExtensionManager()
        : this(MacBundleLayout.Current)
    {
    }

    public FilterExtensionManager(MacBundleLayout layout)
        : this(
            () => FilterExtensionEnvironment.Probe(layout),
            (path, arguments, timeout, cancellationToken) => ToolProcess.RunAsync(path, arguments, timeout, cancellationToken),
            message => StartupLog.Write("sysext", message))
    {
    }

    public FilterExtensionManager(
        Func<FilterExtensionEnvironment> environment,
        SysextHostRunner host,
        Action<string> log)
    {
        _environment = environment ?? throw new ArgumentNullException(nameof(environment));
        _host = host ?? throw new ArgumentNullException(nameof(host));
        _log = log ?? throw new ArgumentNullException(nameof(log));
    }

    public bool IsAvailable
    {
        get
        {
            var environment = _environment();
            return environment.IsMacOS && environment.IsInsideAppBundle && environment.HostPresent;
        }
    }

    /// <summary>The path used by the most recent call (for logs and tests).</summary>
    public FilterExtensionPath LastPath { get; private set; }

    public Task<FilterExtensionStatus> StatusAsync(CancellationToken cancellationToken) =>
        RunAsync("status", StatusTimeoutSeconds, cancellationToken);

    /// <summary>Installs/approves the extension and turns the filter on; waits for the user up to 120 s.</summary>
    public Task<FilterExtensionStatus> ActivateAsync(CancellationToken cancellationToken) =>
        RunAsync("activate", ActivateTimeoutSeconds, cancellationToken);

    /// <summary>Removes the extension (macOS asks for an administrator password).</summary>
    public Task<FilterExtensionStatus> DeactivateAsync(CancellationToken cancellationToken) =>
        RunAsync("deactivate", ActivateTimeoutSeconds, cancellationToken);

    public Task<FilterExtensionStatus> EnableAsync(CancellationToken cancellationToken) =>
        RunAsync("enable", EnableTimeoutSeconds, cancellationToken);

    private async Task<FilterExtensionStatus> RunAsync(
        string command,
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        var environment = _environment();
        if (!environment.IsMacOS)
        {
            return FilterExtensionStatus.Unavailable(command, "The network filter exists only on macOS.");
        }

        if (!environment.IsInsideAppBundle || !environment.HostPresent)
        {
            return FilterExtensionStatus.Unavailable(
                command,
                "This Axiom installation has no network filter host (AxiomFilterHost.app). Install the signed Axiom package.");
        }

        if (!environment.HostInApplicationsFolder && !string.Equals(command, "status", StringComparison.Ordinal))
        {
            return FilterExtensionStatus.Unavailable(
                command,
                "Move AxiomFilterHost.app to /Applications first: macOS only activates network filters from there.");
        }

        return await RunHostAsync(command, timeoutSeconds, environment, cancellationToken).ConfigureAwait(false);
    }

    private async Task<FilterExtensionStatus> RunHostAsync(
        string command,
        int timeoutSeconds,
        FilterExtensionEnvironment environment,
        CancellationToken cancellationToken)
    {
        string[] arguments = command is "status" or "activate"
            ? [command, "--timeout", timeoutSeconds.ToString(CultureInfo.InvariantCulture)]
            : [command];
        var processTimeout = TimeSpan.FromSeconds(timeoutSeconds + 30);

        var result = await _host(environment.HostPath, arguments, processTimeout, cancellationToken).ConfigureAwait(false);
        LastPath = FilterExtensionPath.Host;
        if (result.TimedOut)
        {
            _log($"{command} via host ({environment.HostPath}) timed out after {processTimeout.TotalSeconds:0} s.");
            return new FilterExtensionStatus(command, FilterExtensionStatus.ExitTimeout, false, "timeout", null, false, false);
        }

        if (result.ExitCode == ToolProcessResult.NotStartedExitCode)
        {
            _log($"{command} via host ({environment.HostPath}) could not start: {Tail(result.StandardError)}");
            return FilterExtensionStatus.Unavailable(command, "The activation host could not run: " + result.StandardError);
        }

        var status = FilterExtensionStatus.Parse(command, result.ExitCode, result.StandardOutput);
        _log(
            $"{command} via host ({environment.HostPath}) exit={result.ExitCode} state={status.State} enabled={status.FilterEnabled}" +
            (status.Ok ? string.Empty : " stderr=" + Tail(result.StandardError)));
        return status;
    }

    private static string Tail(string text)
    {
        var trimmed = text.Trim().ReplaceLineEndings(" | ");
        return trimmed.Length <= 400 ? trimmed : trimmed[^400..];
    }
}
