// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text.Json;
using Axiom.Contracts;
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
        new(command, ExitError, false, "unavailable", message, false, false);

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
            return new FilterExtensionStatus(command, exitCode, false, "error", "axiom-sysext printed invalid JSON.", false, false);
        }
    }

    /// <summary>
    /// Parses the JSON returned by <c>libAxiomSysext.dylib</c>. The library cannot exit, so the exit
    /// code the helper would have used travels in the <c>exitCode</c> field (0 ok, 1 error,
    /// 2 timeout, 3 needs approval, 4 reboot required); without it <c>ok</c> decides.
    /// </summary>
    public static FilterExtensionStatus FromLibrary(string command, string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return new FilterExtensionStatus(command, ExitError, false, "error", "libAxiomSysext returned no status.", false, false);
        }

        var exitCode = ExitError;
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Object)
            {
                if (root.TryGetProperty("exitCode", out var code) &&
                    code.ValueKind == JsonValueKind.Number &&
                    code.TryGetInt32(out var value))
                {
                    exitCode = value;
                }
                else if (root.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.True)
                {
                    exitCode = ExitOk;
                }
            }
        }
        catch (JsonException)
        {
            return new FilterExtensionStatus(command, ExitError, false, "error", "libAxiomSysext returned invalid JSON.", false, false);
        }

        return Parse(command, exitCode, json);
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

    /// <summary><c>libAxiomSysext.dylib</c> called in-process from the main executable.</summary>
    Library,

    /// <summary>The <c>axiom-sysext</c> child process.</summary>
    Helper,
}

/// <summary>Runs the helper executable; replaced in tests.</summary>
public delegate Task<ToolProcessResult> SysextHelperRunner(
    string path,
    string[] arguments,
    TimeSpan timeout,
    CancellationToken cancellationToken);

/// <summary>Facts about the host that decide whether and how the filter can be managed.</summary>
public sealed record FilterExtensionEnvironment(
    bool IsMacOS,
    bool IsInsideAppBundle,
    bool IsInApplicationsFolder,
    string HelperPath,
    bool HelperPresent)
{
    public static FilterExtensionEnvironment Probe(MacBundleLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        return new FilterExtensionEnvironment(
            OperatingSystem.IsMacOS(),
            layout.IsInsideAppBundle,
            layout.IsInApplicationsFolder,
            layout.SysextHelperPath,
            File.Exists(layout.SysextHelperPath));
    }
}

/// <summary>
/// Manages the AxiomFilter system extension (activate | deactivate | enable | status …). Prefers
/// the in-process <c>libAxiomSysext.dylib</c> (review #4: the main executable submits the
/// <c>OSSystemExtensionRequest</c>, so Developer ID entitlements and the profile line up) and
/// falls back to the bundled <c>Contents/MacOS/axiom-sysext</c> child process when the dylib is
/// missing or cannot be loaded. Both must run from inside Axiom.app; outside a bundle the manager
/// reports "unavailable". Which path ran is logged to desktop.log and exposed as <see cref="LastPath"/>.
/// </summary>
public sealed class FilterExtensionManager
{
    private const int StatusTimeoutSeconds = 15;

    private const int ActivateTimeoutSeconds = 120;

    private const int EnableTimeoutSeconds = 60;

    private readonly Func<FilterExtensionEnvironment> _environment;

    private readonly ISysextLibrary? _library;

    private readonly SysextHelperRunner _helper;

    private readonly Action<string> _log;

    public FilterExtensionManager()
        : this(MacBundleLayout.Current)
    {
    }

    public FilterExtensionManager(MacBundleLayout layout)
        : this(
            () => FilterExtensionEnvironment.Probe(layout),
            new DylibSysextLibrary((layout ?? throw new ArgumentNullException(nameof(layout))).SysextLibraryPath),
            (path, arguments, timeout, cancellationToken) => ToolProcess.RunAsync(path, arguments, timeout, cancellationToken),
            message => StartupLog.Write("sysext", message))
    {
    }

    public FilterExtensionManager(
        Func<FilterExtensionEnvironment> environment,
        ISysextLibrary? library,
        SysextHelperRunner helper,
        Action<string> log)
    {
        _environment = environment ?? throw new ArgumentNullException(nameof(environment));
        _library = library;
        _helper = helper ?? throw new ArgumentNullException(nameof(helper));
        _log = log ?? throw new ArgumentNullException(nameof(log));
    }

    public bool IsAvailable
    {
        get
        {
            var environment = _environment();
            return environment.IsMacOS && environment.IsInsideAppBundle &&
                   (environment.HelperPresent || _library is { IsPresent: true });
        }
    }

    /// <summary>The path used by the most recent call (for logs and tests).</summary>
    public FilterExtensionPath LastPath { get; private set; }

    public Task<FilterExtensionStatus> StatusAsync(CancellationToken cancellationToken) =>
        RunAsync("status", SysextLibraryCommand.Status, StatusTimeoutSeconds, cancellationToken);

    /// <summary>Installs/approves the extension and turns the filter on; waits for the user up to 120 s.</summary>
    public Task<FilterExtensionStatus> ActivateAsync(CancellationToken cancellationToken) =>
        RunAsync("activate", SysextLibraryCommand.Activate, ActivateTimeoutSeconds, cancellationToken);

    /// <summary>Removes the extension (macOS asks for an administrator password).</summary>
    public Task<FilterExtensionStatus> DeactivateAsync(CancellationToken cancellationToken) =>
        RunAsync("deactivate", SysextLibraryCommand.Deactivate, ActivateTimeoutSeconds, cancellationToken);

    public Task<FilterExtensionStatus> EnableAsync(CancellationToken cancellationToken) =>
        RunAsync("enable", SysextLibraryCommand.Enable, EnableTimeoutSeconds, cancellationToken);

    private async Task<FilterExtensionStatus> RunAsync(
        string command,
        SysextLibraryCommand libraryCommand,
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        var environment = _environment();
        if (!environment.IsMacOS)
        {
            return FilterExtensionStatus.Unavailable(command, "The network filter exists only on macOS.");
        }

        var libraryPresent = _library is { IsPresent: true };
        if (!environment.IsInsideAppBundle || (!environment.HelperPresent && !libraryPresent))
        {
            return FilterExtensionStatus.Unavailable(
                command,
                "This Axiom build has no network filter (axiom-sysext and libAxiomSysext.dylib are missing from Axiom.app).");
        }

        if (!environment.IsInApplicationsFolder && !string.Equals(command, "status", StringComparison.Ordinal))
        {
            return FilterExtensionStatus.Unavailable(
                command,
                "Move Axiom.app to /Applications first: macOS only activates network filters from there.");
        }

        if (libraryPresent)
        {
            var viaLibrary = await RunLibraryAsync(command, libraryCommand, timeoutSeconds, cancellationToken).ConfigureAwait(false);
            if (viaLibrary is not null)
            {
                return viaLibrary;
            }

            if (!environment.HelperPresent)
            {
                LastPath = FilterExtensionPath.None;
                return FilterExtensionStatus.Unavailable(
                    command,
                    "libAxiomSysext.dylib could not be loaded and axiom-sysext is missing from Axiom.app.");
            }
        }

        return await RunHelperAsync(command, timeoutSeconds, environment, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Returns null when the dylib cannot be used and the helper should run instead.</summary>
    private async Task<FilterExtensionStatus?> RunLibraryAsync(
        string command,
        SysextLibraryCommand libraryCommand,
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        var library = _library!;
        try
        {
            // The call blocks for up to timeoutSeconds (+5 s) while the Swift side waits on its
            // semaphore; keep it off the UI thread on a dedicated thread, not a pool thread.
            var json = await Task.Factory.StartNew(
                () => library.Invoke(libraryCommand, timeoutSeconds),
                cancellationToken,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default).ConfigureAwait(false);

            var status = FilterExtensionStatus.FromLibrary(command, json);
            LastPath = FilterExtensionPath.Library;
            _log(string.Create(
                CultureInfo.InvariantCulture,
                $"{command} via dylib ({library.Path}) exit={status.ExitCode} state={status.State} enabled={status.FilterEnabled}") +
                (status.Ok ? string.Empty : " message=" + Tail(status.Message ?? string.Empty)));
            return status;
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            _log($"{command}: libAxiomSysext.dylib unusable ({exception.GetType().Name}: {Tail(exception.Message)}); falling back to axiom-sysext.");
            return null;
        }
    }

    private async Task<FilterExtensionStatus> RunHelperAsync(
        string command,
        int timeoutSeconds,
        FilterExtensionEnvironment environment,
        CancellationToken cancellationToken)
    {
        string[] arguments = command is "status" or "activate"
            ? [command, "--timeout", timeoutSeconds.ToString(CultureInfo.InvariantCulture)]
            : [command];
        var processTimeout = TimeSpan.FromSeconds(timeoutSeconds + 30);

        var result = await _helper(environment.HelperPath, arguments, processTimeout, cancellationToken).ConfigureAwait(false);
        LastPath = FilterExtensionPath.Helper;
        if (result.TimedOut)
        {
            _log($"{command} via helper ({environment.HelperPath}) timed out after {processTimeout.TotalSeconds:0} s.");
            return new FilterExtensionStatus(command, FilterExtensionStatus.ExitTimeout, false, "timeout", null, false, false);
        }

        if (result.ExitCode == ToolProcessResult.NotStartedExitCode)
        {
            _log($"{command} via helper ({environment.HelperPath}) could not start: {Tail(result.StandardError)}");
            return FilterExtensionStatus.Unavailable(command, "axiom-sysext could not run: " + result.StandardError);
        }

        var status = FilterExtensionStatus.Parse(command, result.ExitCode, result.StandardOutput);
        _log(
            $"{command} via helper ({environment.HelperPath}) exit={result.ExitCode} state={status.State} enabled={status.FilterEnabled}" +
            (status.Ok ? string.Empty : " stderr=" + Tail(result.StandardError)));
        return status;
    }

    private static string Tail(string text)
    {
        var trimmed = text.Trim().ReplaceLineEndings(" | ");
        return trimmed.Length <= 400 ? trimmed : trimmed[^400..];
    }
}
