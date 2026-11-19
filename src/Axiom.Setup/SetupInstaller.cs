// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;
using Axiom.Contracts.Blackbox;
using Axiom.Contracts.Enforcement;
using Axiom.Presentation;

namespace Axiom.Setup;

internal sealed record ExistingInstallationInfo(
    bool Exists,
    string? Version,
    string? DesktopPath,
    string? ServicePath);

internal sealed record SetupInstallResult(
    bool Success,
    string Message,
    IReadOnlyList<string> Log,
    string? Warning = null,
    bool CoreInstalled = false,
    bool PartialSuccess = false);

internal static class SetupInstaller
{
    public static ExistingInstallationInfo DetectExistingInstallation(string installDir)
    {
        if (string.IsNullOrWhiteSpace(installDir))
        {
            return new ExistingInstallationInfo(false, null, null, null);
        }

        var desktop = Path.Combine(installDir, "Axiom.Desktop.exe");
        var service = Path.Combine(installDir, "Axiom.Service.exe");
        var exists = File.Exists(desktop) || File.Exists(service);
        string? version = null;

        var manifestPath = Path.Combine(installDir, "install.json");
        if (File.Exists(manifestPath))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(manifestPath));
                if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                    doc.RootElement.TryGetProperty("version", out var v) &&
                    v.ValueKind == JsonValueKind.String)
                {
                    version = v.GetString();
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
            {
            }
        }

        if (string.IsNullOrWhiteSpace(version) && File.Exists(desktop))
        {
            version = FileVersionInfo.GetVersionInfo(desktop).ProductVersion;
        }

        return new ExistingInstallationInfo(
            exists,
            string.IsNullOrWhiteSpace(version) ? null : version,
            File.Exists(desktop) ? desktop : null,
            File.Exists(service) ? service : null);
    }
    private const string PayloadPrefix = "Axiom.Setup.Payload.";

    private static readonly JsonSerializerOptions ManifestJsonOptions = new()
    {
        WriteIndented = true,
    };

    private static readonly HttpClient ProbeClient = new()
    {
        Timeout = TimeSpan.FromSeconds(3),
    };

    public static async Task<SetupInstallResult> InstallAsync(
        SetupOptions options,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        var log = new List<string>();
        // Every step is timestamped so the UI and the log show how long a slow phase has been
        // running; a complete install can legitimately take 10-20 minutes.
        var clock = System.Diagnostics.Stopwatch.StartNew();
        void Report(string message)
        {
            var line = string.Create(CultureInfo.InvariantCulture, $"[{clock.Elapsed:mm\\:ss}] {message}");
            log.Add(line);
            progress?.Report(line);
        }

        try
        {
            if (!StopRunningDesktopProcesses(Report))
            {
                return new SetupInstallResult(false, "Axiom is running and could not be closed automatically.", log);
            }

            var tempDir = Path.Combine(Path.GetTempPath(), "axiom-setup-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);

            try
            {
                var payload = await ExtractPayloadAsync(tempDir, Report, cancellationToken).ConfigureAwait(false);
                if (!payload.HasDesktop || !payload.HasService)
                {
                    return new SetupInstallResult(false,
                        "The setup payload is incomplete. Use the official Axiom release.", log);
                }

                if (StorageSafety.IsReparsePointInPath(options.InstallDir))
                {
                    return new SetupInstallResult(
                        false,
                        "Install location contains a junction or symbolic link. Choose a normal directory.",
                        log);
                }

                Directory.CreateDirectory(options.InstallDir);
                var existing = DetectExistingInstallation(options.InstallDir);
                if (existing.Exists)
                {
                    Report($"Existing Axiom installation detected at {options.InstallDir}" +
                           $"{(existing.Version is null ? "" : $" (v{existing.Version})")}; upgrading in place.");
                }

                StopInstallDirServiceProcesses(options.InstallDir, Report);
                Report($"Installing to {options.InstallDir}");

                var desktopTarget = Path.Combine(options.InstallDir, "Axiom.Desktop.exe");
                var serviceTarget = Path.Combine(options.InstallDir, "Axiom.Service.exe");
                CopyFile(payload.DesktopPath!, desktopTarget, overwrite: true);
                CopyFile(payload.ServicePath!, serviceTarget, overwrite: true);

                var communityTarget = Path.Combine(options.InstallDir, "community", "feed.json");
                if (payload.CommunityPath is not null)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(communityTarget)!);
                    CopyFile(payload.CommunityPath, communityTarget, overwrite: true);
                }

                var version = FileVersionInfo.GetVersionInfo(desktopTarget).ProductVersion ?? "0.0.0";
                var manifest = new
                {
                    product = "Axiom",
                    version,
                    sha256 = HashFile(desktopTarget),
                    serviceSha256 = HashFile(serviceTarget),
                    installedUtc = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                    source = "Axiom.Setup",
                };
                await File.WriteAllTextAsync(
                    Path.Combine(options.InstallDir, "install.json"),
                    JsonSerializer.Serialize(manifest, ManifestJsonOptions),
                    cancellationToken).ConfigureAwait(false);
                Report($"Installed Axiom {version}");
                CleanupLegacyInstall();
                Report("Removed legacy executable and shortcut names.");

                var blackboxInstalled = false;
                var dkgInstalled = false;
                var blackboxExit = false;
                var dkgStepSucceeded = false;
                var serviceRegisteredEarly = false;
                string? upgradeWarning = null;
                var partialIssues = new List<string>();
                if (options.CompleteInstallation)
                {
                    serviceRegisteredEarly = SetupDefaults.EnsureServiceRegistered(options.InstallDir, Report);
                    Report("Complete installation selected: Blackbox, DKG and agent hooks will be configured.");
                    Report("Complete installation may take 10-20 minutes: service registration, the verified " +
                           "Blackbox download/install, a local DKG node and the agent hooks run in sequence.");
                    var setupProtection = new UserStateProtection();
                    var setupSnapshot = await Task.Run(
                        () => setupProtection.Capture(),
                        cancellationToken).ConfigureAwait(false);
                    var moduleInstaller = new OptionalModuleInstaller();

                    // The vendor installer owns the Blackbox tree. Back up the findings, history and
                    // identity first so an update can never silently drop them.
                    var upgradeBackup = UpgradeDataGuard.Capture();
                    if (upgradeBackup is not null)
                    {
                        Report($"Protected data backup: {upgradeBackup.Entries.Count} file(s), " +
                               $"{upgradeBackup.TotalBytes / 1_048_576.0:F1} MB at {upgradeBackup.Directory}.");
                    }

                    var prereqs = Axiom.Contracts.Modules.ModulePrerequisites.Probe();
                    var includeVcRedist = !OptionalModuleInstaller.HasVcRuntime();
                    if (!prereqs.IsSatisfied || includeVcRedist)
                    {
                        Report($"Checking module prerequisites (missing: {(prereqs.IsSatisfied ? "VC++ x64 redistributable" : prereqs.MissingSummary)}; VC++ x64={(includeVcRedist ? "missing" : "ready")})...");
                        var prereqReady = await Task.Run(
                            () => moduleInstaller.InstallPrerequisitesAndWait(prereqs, includeVcRedist, Report),
                            cancellationToken).ConfigureAwait(false);
                        Report(prereqReady
                            ? "Module prerequisites are ready."
                            : $"Module prerequisite installation incomplete: {moduleInstaller.LastError ?? "see log above"}");
                    }

                    Report("Auditing official installer scope: Axiom modules, Hermes plugin config/mode and scheduled task only.");
                    var blackboxPrereqs = Axiom.Contracts.Modules.ModulePrerequisites.Probe();
                    if (!blackboxPrereqs.IsSatisfied)
                    {
                        var pythonNote = blackboxPrereqs.RejectedPythonVersions.Count == 0
                            ? string.Empty
                            : $" Found incompatible Python: {string.Join(", ", blackboxPrereqs.RejectedPythonVersions)}.";
                        Report(
                            $"Blackbox was not installed: the vendor installer requires " +
                            $"{blackboxPrereqs.MissingSummary}.{pythonNote} " +
                            "Axiom core is installed. Install the missing tools (Python 3.11-3.13, preferably 3.12), " +
                            "then click Repair on the Blackbox card.");
                        blackboxExit = false;
                    }
                    else
                    {
                        Report("Configuring the official Blackbox runtime silently in the background...");
                        blackboxExit = await Task.Run(
                            () => moduleInstaller.InstallBlackboxAndWait(Report),
                            cancellationToken).ConfigureAwait(false);
                        Report($"Blackbox installer exit code: {(blackboxExit ? "0" : "non-zero")}.");
                        if (blackboxExit && !LocalModuleRuntime.IsPortListening(LocalModuleRuntime.BlackboxPort))
                        {
                            Report("Starting the installed Blackbox dashboard...");
                            moduleInstaller.StartBlackboxDashboard();
                        }
                    }

                    if (upgradeBackup is not null)
                    {
                        var dataCheck = UpgradeDataGuard.VerifyAndRestore(upgradeBackup.Directory);
                        var intact = upgradeBackup.Entries.Count - dataCheck.Restored.Count - dataCheck.Shrunk.Count;
                        Report($"Upgrade data check: {intact} intact, {dataCheck.Restored.Count} restored, " +
                               $"{dataCheck.Shrunk.Count} smaller than the backup, {dataCheck.Failed.Count} failed.");
                        if (!dataCheck.Ok)
                        {
                            upgradeWarning =
                                $"{dataCheck.Failed.Count} protected file(s) could not be restored. " +
                                $"The pre-upgrade copy is kept at {upgradeBackup.Directory}.";
                        }
                    }

                    var storageReport = await Task.Run(
                        () => ModuleStorageMaintenance.RunOnce(),
                        cancellationToken).ConfigureAwait(false);
                    if (storageReport.DkgConfigsUpdated > 0 ||
                        storageReport.TrimmedLogs > 0 ||
                        storageReport.RemovedFiles > 0)
                    {
                        Report($"Storage hygiene: updated {storageReport.DkgConfigsUpdated} DKG WAL policy config(s), " +
                               $"trimmed {storageReport.TrimmedLogs} log(s), removed {storageReport.RemovedFiles} rotated log(s) " +
                               $"({storageReport.ReclaimedBytes / 1_048_576.0:F1} MB reclaimed).");
                    }

                    var blackboxProvidesDkg = blackboxExit &&
                                              await TryWaitForBlackboxDkgAsync(cancellationToken).ConfigureAwait(false);
                    if (blackboxProvidesDkg)
                    {
                        Report("Blackbox reports its own DKG node reachable; skipping Axiom's standalone DKG " +
                               "to avoid a second unused node on this machine.");
                        dkgInstalled = true;
                        dkgStepSucceeded = true;
                    }
                    else
                    {
                        // If the Hermes config already names a DKG home, start that node instead of
                        // initializing a second home the guard would never read (#307).
                        if (moduleInstaller.StartDkg())
                        {
                            Report("Started the DKG node the Hermes config names; no second home was created.");
                            dkgStepSucceeded = true;
                        }
                        else
                        {
                            Report("Configuring the official DKG node silently in the background...");
                            dkgStepSucceeded = await Task.Run(
                                () => moduleInstaller.InstallDkgAndWait(Report),
                                cancellationToken).ConfigureAwait(false);
                            Report($"DKG installer exit code: {(dkgStepSucceeded ? "0" : "non-zero")}.");
                        }
                    }

                    var hermesLocal = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "hermes");
                    var expectedInstallerPaths = new[]
                    {
                        Path.Combine(hermesLocal, "config.yaml"),
                        Path.Combine(hermesLocal, "plugins"),
                        Path.Combine(hermesLocal, "blackbox"),
                        Path.Combine(hermesLocal, "bin"),
                        Path.Combine(hermesLocal, "installs"),
                        Path.Combine(hermesLocal, "cache"),
                        Path.Combine(hermesLocal, "logs"),
                        Path.Combine(hermesLocal, "backups"),
                        Path.Combine(hermesLocal, "audio_cache"),
                        Path.Combine(hermesLocal, "image_cache"),
                        Path.Combine(
                            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                            ".hermes",
                            "config.yaml"),
                    };
                    var setupChanges = await Task.Run(
                        () => setupProtection.Verify(setupSnapshot, expectedInstallerPaths),
                        cancellationToken).ConfigureAwait(false);
                    if (setupChanges.Count > 0)
                    {
                        var restoreFailures = await Task.Run(
                            () => setupProtection.Restore(setupSnapshot, setupChanges),
                            cancellationToken).ConfigureAwait(false);
                        Report($"Protected user-state check: {setupChanges.Count} out-of-scope MCP/model/favorite/session/Antigravity/Gemini change(s) detected; " +
                               $"{restoreFailures.Count} restore failure(s).");
                        if (restoreFailures.Count > 0)
                        {
                            Report("WARNING: some protected user-state files could not be restored while the " +
                                   "desktop and DKG were running; the installation continues. Review the listed " +
                                   "MCP/model/favorite/session files after the upgrade.");
                        }
                    }
                    else
                    {
                        Report("Protected user-state check: MCP servers, models, favorites, sessions and Antigravity/Gemini history were unchanged.");
                    }

                    blackboxInstalled = await WaitForEndpointAsync(
                        "http://127.0.0.1:9700/api/graph-status", cancellationToken).ConfigureAwait(false);

                    // #307: the node, the guard and the CLI must agree on one DKG home. Probe the
                    // resolved home's own port and token and prove the identity endpoint accepts it.
                    var dkgHome = DkgHomeResolver.ResolveEffective(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        ReadConfigOrNull,
                        Directory.Exists);
                    var dkgIdentity = await WaitForDkgIdentityAsync(dkgHome, Report, cancellationToken)
                        .ConfigureAwait(false);
                    dkgInstalled = dkgIdentity.Verified;

                    Report($"Blackbox endpoint: {(blackboxInstalled ? "connected" : "not verified")}; " +
                           $"DKG endpoint: {(dkgInstalled ? (blackboxProvidesDkg ? "provided by Blackbox" : "connected") : "not verified")}.");
                    Report(dkgIdentity.Summary + ".");
                    if (!dkgIdentity.Verified)
                    {
                        Report("WARNING: findings cannot be written to the local graph until the DKG " +
                               "identity check passes; check that hermes config.yaml, the guard and the " +
                               "node use this home.");
                    }

                    Report("Installing agent hooks after the Blackbox runtime is prepared.");
                    var enforcementPolicy = EnforcementPolicyProvisioner.EnsureDefault();
                    Report(enforcementPolicy is null
                        ? "OS enforcement policy: an existing policy was kept (the service provisions one when absent)."
                        : "OS enforcement policy: default written so the service can enforce protected credential stores.");
                    var protection = new UserStateProtection();
                    var protectedBefore = await Task.Run(
                        () => protection.Capture(),
                        cancellationToken).ConfigureAwait(false);
                    var openCodeProtection = new OpenCodeProtection();
                    var codexProtection = new CodexProtection();
                    var claudeProtection = new ClaudeProtection();
                    var antigravityProtection = new AntigravityProtection();
                    var cursorProtection = new CursorProtection();
                    var copilotProtection = new CopilotProtection();
                    var geminiProtection = new GeminiProtection();
                    var windsurfProtection = new WindsurfProtection();
                    var clineProtection = new ClineProtection();
                    var zCodeProtection = new ZCodeProtection();
                    var deepSeekProtection = new DeepSeekProtection();
                    var openCode = openCodeProtection.EnsureInstalled();
                    var codex = codexProtection.EnsureInstalled();
                    var claude = claudeProtection.EnsureInstalled();
                    var antigravity = antigravityProtection.EnsureInstalled();
                    var cursor = cursorProtection.EnsureInstalled();
                    var copilot = copilotProtection.EnsureInstalled();
                    var gemini = geminiProtection.EnsureInstalled();
                    var windsurf = windsurfProtection.EnsureInstalled();
                    var cline = clineProtection.EnsureInstalled();
                    var zCode = zCodeProtection.EnsureInstalled();
                    var deepSeek = deepSeekProtection.EnsureInstalled();
                    var unexpectedChanges = await Task.Run(
                        () => protection.Verify(
                            protectedBefore,
                            [
                                openCodeProtection.PluginPath,
                                openCodeProtection.V1PluginPath,
                                openCodeProtection.LegacyPluginPath,
                                openCodeProtection.BridgePath,
                                openCodeProtection.PreRenamePluginDirectory,
                                openCodeProtection.PreRenameV1PluginPath,
                                openCodeProtection.PreRenameSingularPluginPath,
                                openCodeProtection.PreRenameBridgePath,
                                codexProtection.HooksPath,
                                codexProtection.HookScriptPath,
                                claudeProtection.SettingsPath,
                                claudeProtection.HookScriptPath,
                                antigravityProtection.HooksPath,
                                antigravityProtection.HookScriptPath,
                                cursorProtection.HooksPath,
                                cursorProtection.HookScriptPath,
                                copilotProtection.HooksPath,
                                copilotProtection.HookScriptPath,
                                copilotProtection.PreRenameHooksPath,
                                geminiProtection.SettingsPath,
                                geminiProtection.HookScriptPath,
                                windsurfProtection.HooksPath,
                                windsurfProtection.HookScriptPath,
                                clineProtection.HookPath,
                                zCodeProtection.ConfigPath,
                                zCodeProtection.HookScriptPath,
                                deepSeekProtection.HooksPath,
                                deepSeekProtection.PatchPath,
                                deepSeekProtection.HookScriptPath,
                            ]),
                        cancellationToken).ConfigureAwait(false);
                    if (unexpectedChanges.Count > 0)
                    {
                        var restoreFailures = await Task.Run(
                            () => protection.Restore(protectedBefore, unexpectedChanges),
                            cancellationToken).ConfigureAwait(false);
                        Report($"Agent hooks: protected user-state check failed ({unexpectedChanges.Count} change(s)); " +
                               $"{restoreFailures.Count} restore failure(s). MCP/model/favorite/session/Antigravity files must be reviewed.");
                        if (restoreFailures.Count > 0)
                        {
                            Report("WARNING: some agent-hook protected files could not be restored; the " +
                                   "installation continues. Review the MCP/model/favorite/session files.");
                        }
                    }
                    else
                    {
                        Report("Agent hooks: MCP server definitions, selected models, favorites, sessions and Antigravity history were not changed.");
                    }

                    Report($"Agent hooks: OpenCode/OpenChamber {(openCode ? "installed" : "skipped")}, " +
                           $"Codex {(codex ? "installed" : "skipped")}, Claude Code {(claude ? "installed" : "skipped")}, " +
                           $"Antigravity {(antigravity ? "installed" : "skipped")}, " +
                           $"Cursor {(cursor ? "installed" : "skipped")}, " +
                           $"GitHub Copilot CLI {(copilot ? "installed" : "skipped")}, Gemini CLI {(gemini ? "installed" : "skipped")}, " +
                           $"Windsurf Cascade {(windsurf ? "installed" : "skipped")}, Cline {(cline ? "installed" : "skipped")}, " +
                           $"ZCode {(zCode ? "installed" : "skipped")}, DeepSeek Harness {(deepSeek ? "installed" : "skipped")}.");
                }
                else
                {
                    Report("Partial installation selected: no Blackbox, DKG or agent hook files were changed.");
                }

                string? warning = null;
                if (options.CompleteInstallation)
                {
                    if (!blackboxExit || !blackboxInstalled)
                    {
                        partialIssues.Add(
                            "Blackbox runtime did not install cleanly or could not be reached; Blackbox-dependent agent protection remains unavailable until repaired.");
                    }

                    if (!dkgStepSucceeded || !dkgInstalled)
                    {
                        partialIssues.Add(
                            "DKG node could not be initialized or verified (install Node.js LTS / npm if missing, then click Repair).");
                    }

                    var defaults = await SetupDefaults
                        .ApplyCompleteAsync(options.InstallDir, Report, cancellationToken, serviceRegisteredEarly,
                            options.AllowManualThreatSharing)
                        .ConfigureAwait(false);
                    if (!string.IsNullOrWhiteSpace(defaults.Warning))
                    {
                        partialIssues.Add(defaults.Warning);
                    }

                    if (!string.IsNullOrWhiteSpace(upgradeWarning))
                    {
                        partialIssues.Add(upgradeWarning);
                    }

                    if (partialIssues.Count > 0)
                    {
                        warning = string.Join("\n\n", partialIssues.Distinct(StringComparer.Ordinal));
                    }
                }
                else
                {
                    SetupDefaults.WritePartialProfile();
                    Report("Partial installation: Axiom Shield, Privacy Shield, autostart and optional modules stay off until you enable them.");
                }

                if (!OnboardingStore.IsCompleted)
                {
                    OnboardingStore.Save(new OnboardingSettings(
                        Completed: true,
                        Skipped: true,
                        Dkg: dkgInstalled,
                        Blackbox: blackboxInstalled));
                    Report("First-run configuration completed; optional modules remain available on Security.");
                }

                if (options.CreateShortcut)
                {
                    if (CreateStartMenuShortcut(desktopTarget, options.InstallDir))
                    {
                        Report("Created Start Menu shortcut");
                    }
                    else
                    {
                        Report("Could not create the Start Menu shortcut; the application is still installed.");
                    }
                }

                var partialSuccess = partialIssues.Count > 0;
                SaveLastSetupWarning(warning);
                if (options.StartAfterInstall)
                {
                    try
                    {
                        using var started = Process.Start(new ProcessStartInfo(desktopTarget)
                        {
                            UseShellExecute = true,
                            WorkingDirectory = options.InstallDir,
                        });
                        Report("Started Axiom");
                    }
                    catch (Exception exception) when (exception is
                                 System.ComponentModel.Win32Exception or InvalidOperationException)
                    {
                        Report("Axiom was installed, but could not start automatically: " + exception.Message);
                    }
                }

                var resultMessage = partialSuccess
                    ? "Axiom core application and local service were installed, with optional-module warnings (partial success). Use Open Axiom, Repair after installing prerequisites, or Uninstall."
                    : "Axiom was installed successfully.";

                return new SetupInstallResult(
                    Success: true,
                    Message: resultMessage,
                    Log: log,
                    Warning: warning,
                    CoreInstalled: true,
                    PartialSuccess: partialSuccess);
            }
            finally
            {
                try
                {
                    Directory.Delete(tempDir, recursive: true);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                }
            }
        }
        catch (OperationCanceledException)
        {
            return new SetupInstallResult(false, "Installation was cancelled.", log);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new SetupInstallResult(false, "Installation failed: " + exception.Message, log);
        }
    }

    private static bool StopRunningDesktopProcesses(Action<string> report)
    {
        var running = Process.GetProcessesByName("Axiom.Desktop")
            .Concat(Process.GetProcessesByName("Netpetra.Desktop"))
            .ToArray();
        if (running.Length == 0)
        {
            return true;
        }

        report($"Closing {running.Length} running Axiom desktop process(es)...");
        try
        {
            foreach (var proc in running)
            {
                try
                {
                    if (!proc.HasExited)
                    {
                        _ = proc.CloseMainWindow();
                        if (!proc.WaitForExit(2500))
                        {
                            proc.Kill(entireProcessTree: true);
                            _ = proc.WaitForExit(3000);
                        }
                    }
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                {
                }
            }

            Thread.Sleep(250);
            return !AnyProcessRunning("Axiom.Desktop", "Netpetra.Desktop");
        }
        finally
        {
            foreach (var proc in running)
            {
                proc.Dispose();
            }
        }
    }

    private static bool AnyProcessRunning(params string[] processNames)
    {
        foreach (var name in processNames)
        {
            var processes = Process.GetProcessesByName(name);
            var any = processes.Length > 0;
            foreach (var process in processes)
            {
                process.Dispose();
            }

            if (any)
            {
                return true;
            }
        }

        return false;
    }

    public static async Task<SetupInstallResult> UninstallAsync(
        SetupOptions options,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        var log = new List<string>();
        var clock = Stopwatch.StartNew();
        void Report(string message)
        {
            var line = string.Create(CultureInfo.InvariantCulture, $"[{clock.Elapsed:mm\\:ss}] {message}");
            log.Add(line);
            progress?.Report(line);
        }

        try
        {
            if (AnyProcessRunning("Axiom.Desktop", "Netpetra.Desktop"))
            {
                return new SetupInstallResult(false, "Axiom is running. Close it before uninstalling.", log);
            }

            if (StorageSafety.IsReparsePointInPath(options.InstallDir))
            {
                return new SetupInstallResult(
                    false,
                    "Install location contains a junction or symbolic link. Refusing to uninstall from an unsafe path.",
                    log);
            }

            Report($"Uninstalling Axiom from {options.InstallDir}...");
            StopInstallDirServiceProcesses(options.InstallDir, Report);

            string? warning = null;
            var serviceExe = Path.Combine(options.InstallDir, "Axiom.Service.exe");
            var protectedServiceExe = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Axiom",
                "Axiom.Service.exe");
            var uninstallHelper = File.Exists(serviceExe)
                ? serviceExe
                : File.Exists(protectedServiceExe)
                    ? protectedServiceExe
                    : null;

            if (uninstallHelper is not null && await IsWindowsServiceRegisteredAsync(cancellationToken).ConfigureAwait(false))
            {
                Report("Removing Axiom Windows service registration (elevation prompt)...");
                try
                {
                    using var proc = Process.Start(new ProcessStartInfo
                    {
                        FileName = uninstallHelper,
                        Arguments = "--uninstall-service",
                        UseShellExecute = true,
                        Verb = "runas",
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden,
                    });
                    if (proc is not null)
                    {
                        await proc.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                        Report(proc.ExitCode == 0
                            ? "Axiom Windows service removed."
                            : $"Axiom service uninstaller exited with code {proc.ExitCode}.");
                        if (proc.ExitCode != 0)
                        {
                            warning = $"Windows service uninstaller exited with code {proc.ExitCode}.";
                        }
                    }
                }
                catch (System.ComponentModel.Win32Exception exception) when (exception.NativeErrorCode == 1223)
                {
                    warning = "Administrator approval was cancelled; the Windows service registration may still exist.";
                    Report(warning);
                }
            }

            try
            {
                using var run = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run",
                    writable: true);
                run?.DeleteValue("Axiom", throwOnMissingValue: false);
                Report("Removed Axiom startup registry entry.");
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                Report("Could not remove startup registry entry: " + exception.Message);
            }

            try
            {
                var shortcut = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Microsoft",
                    "Windows",
                    "Start Menu",
                    "Programs",
                    "Axiom.lnk");
                if (File.Exists(shortcut))
                {
                    File.Delete(shortcut);
                    Report("Removed Start Menu shortcut.");
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                Report("Could not remove Start Menu shortcut: " + exception.Message);
            }

            if (Directory.Exists(options.InstallDir))
            {
                foreach (var fileName in new[] { "Axiom.Desktop.exe", "Axiom.Service.exe", "install.json" })
                {
                    var path = Path.Combine(options.InstallDir, fileName);
                    if (File.Exists(path))
                    {
                        DeleteFileWithRetry(path);
                        Report($"Removed {fileName}.");
                    }
                }

                var communityDir = Path.Combine(options.InstallDir, "community");
                if (Directory.Exists(communityDir))
                {
                    Directory.Delete(communityDir, recursive: true);
                    Report("Removed community feed folder.");
                }

                if (!Directory.EnumerateFileSystemEntries(options.InstallDir).Any())
                {
                    Directory.Delete(options.InstallDir);
                    Report("Removed empty install directory.");
                }
            }

            var userAxiomDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Axiom");
            foreach (var marker in new[] { SetupDefaults.ProfileFileName, "startup.json" })
            {
                var path = Path.Combine(userAxiomDir, marker);
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }

            Report("Axiom uninstall finished.");
            return new SetupInstallResult(true, "Axiom was uninstalled cleanly.", log, warning, CoreInstalled: false, PartialSuccess: false);
        }
        catch (OperationCanceledException)
        {
            return new SetupInstallResult(false, "Uninstall was cancelled.", log);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new SetupInstallResult(false, "Uninstall failed: " + exception.Message, log);
        }
    }

    internal const string WindowsServiceQueryArguments = "query Axiom";

    private static async Task<bool> IsWindowsServiceRegisteredAsync(CancellationToken cancellationToken)
    {
        try
        {
            var scPath = Path.Combine(Environment.SystemDirectory, "sc.exe");
            using var proc = Process.Start(new ProcessStartInfo(scPath, WindowsServiceQueryArguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (proc is null)
            {
                return false;
            }

            await proc.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            return proc.ExitCode == 0;
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return false;
        }
    }

    private static async Task<PayloadPaths> ExtractPayloadAsync(
        string tempDir,
        Action<string> report,
        CancellationToken cancellationToken)
    {
        await TryExtractPayloadArchiveAsync(tempDir, cancellationToken).ConfigureAwait(false);

        var desktop = ExistingOrNull(Path.Combine(tempDir, "Axiom.Desktop.exe"))
            ?? await ExtractResourceAsync(
                PayloadPrefix + "Axiom.Desktop.exe",
                Path.Combine(tempDir, "Axiom.Desktop.exe"),
                cancellationToken).ConfigureAwait(false);
        var service = ExistingOrNull(Path.Combine(tempDir, "Axiom.Service.exe"))
            ?? await ExtractResourceAsync(
                PayloadPrefix + "Axiom.Service.exe",
                Path.Combine(tempDir, "Axiom.Service.exe"),
                cancellationToken).ConfigureAwait(false);
        var community = ExistingOrNull(Path.Combine(tempDir, "community", "feed.json"))
            ?? await ExtractResourceAsync(
                PayloadPrefix + "community.feed.json",
                Path.Combine(tempDir, "community", "feed.json"),
                cancellationToken).ConfigureAwait(false);

        if (desktop is null || service is null)
        {
            report("Embedded payload not found; looking for release files next to setup.");
            desktop ??= ExistingOrNull(Path.Combine(AppContext.BaseDirectory, "Axiom.Desktop.exe"));
            service ??= ExistingOrNull(Path.Combine(AppContext.BaseDirectory, "Axiom.Service.exe"));
            community ??= ExistingOrNull(Path.Combine(AppContext.BaseDirectory, "community", "feed.json"));
        }

        return new PayloadPaths(desktop, service, community);
    }

    private static async Task TryExtractPayloadArchiveAsync(string tempDir, CancellationToken cancellationToken)
    {
        await using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(PayloadPrefix + "zip");
        if (stream is null)
        {
            return;
        }

        var root = Path.GetFullPath(tempDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
        foreach (var entry in archive.Entries)
        {
            if (string.IsNullOrEmpty(entry.Name))
            {
                continue;
            }

            var destination = Path.GetFullPath(Path.Combine(tempDir, entry.FullName));
            if (!destination.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"Archive entry escapes temp directory: {entry.FullName}");
            }

            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            await using var entryStream = entry.Open();
            await using var file = File.Create(destination);
            await entryStream.CopyToAsync(file, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<string?> ExtractResourceAsync(
        string resourceName,
        string destination,
        CancellationToken cancellationToken)
    {
        await using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            return null;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        await using var file = File.Create(destination);
        await stream.CopyToAsync(file, cancellationToken).ConfigureAwait(false);
        return destination;
    }

    private static string? ExistingOrNull(string path) => File.Exists(path) ? path : null;

    /// <summary>
    /// A registered Windows service runs from Program Files and is replaced by the elevated service
    /// installer later, so it must not block a Setup upgrade. Only an interactive service process
    /// that lives in the selected install directory can lock the files being copied.
    /// </summary>
    private static void StopInstallDirServiceProcesses(string installDir, Action<string> report)
    {
        var root = Path.GetFullPath(installDir).TrimEnd(Path.DirectorySeparatorChar) +
                   Path.DirectorySeparatorChar;
        foreach (var name in new[] { "Axiom.Service", "Netpetra.Service" })
        {
            foreach (var process in Process.GetProcessesByName(name))
            {
                try
                {
                    var path = process.MainModule?.FileName;
                    if (path is null ||
                        !Path.GetFullPath(path).StartsWith(root, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    process.Kill(entireProcessTree: true);
                    process.WaitForExit(3000);
                    report($"Stopped {name} from the install directory before copying.");
                }
                catch (Exception exception) when (exception is
                             System.ComponentModel.Win32Exception or InvalidOperationException or
                             NotSupportedException or IOException or UnauthorizedAccessException)
                {
                    // The copy below reports a locked file; never kill an unreadable process.
                }
                finally
                {
                    process.Dispose();
                }
            }
        }
    }

    private static void CopyFile(string source, string destination, bool overwrite)
    {
        // The service may still be releasing its image after a stop request; retry briefly instead
        // of failing the whole upgrade on a sharing violation.
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                File.Copy(source, destination, overwrite);
                return;
            }
            catch (IOException) when (attempt < 10)
            {
                Thread.Sleep(1000);
            }
        }
    }

    internal static void DeleteFileWithRetry(string path)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                File.Delete(path);
                return;
            }
            catch (IOException) when (attempt < 10)
            {
                Thread.Sleep(1000);
            }
        }
    }

    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static async Task<bool> WaitForEndpointAsync(string url, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 30; attempt++)
        {
            try
            {
                using var response = await ProbeClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    return true;
                }
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
            {
            }

            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
        }

        return false;
    }

    /// <summary>
    /// Waits for the resolved DKG home to prove its own token. A 401 does not heal while the node
    /// runs, so it is reported immediately instead of retrying for the full window.
    /// </summary>
    private static async Task<DkgIdentity> WaitForDkgIdentityAsync(
        string home,
        Action<string>? report,
        CancellationToken cancellationToken)
    {
        DkgIdentity? last = null;
        // The node's first start initialises its store before the identity endpoint answers; the lab
        // took well over 30 s, so give it up to 90 s and say what is happening instead of failing
        // with "could not be initialized" while the node is still coming up (issue #381).
        const int attempts = 90;
        for (var attempt = 0; attempt < attempts; attempt++)
        {
            last = await DkgIdentityProbe.CheckAsync(home, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (last.Verified || last.StatusCode is 401)
            {
                return last;
            }

            if (report is not null && attempt is 29 or 59)
            {
                report($"DKG identity not verified after {attempt + 1}s; the node may still be starting " +
                       $"({last.Summary}).");
            }

            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
        }

        return last!;
    }

    private static string? ReadConfigOrNull(string path)
    {
        try
        {
            return File.Exists(path) ? File.ReadAllText(path) : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// True when Blackbox reports that its own DKG node is reachable and gives its loopback URL.
    /// In that case the complete installation skips Axiom's standalone node.
    /// </summary>
    private static async Task<bool> TryWaitForBlackboxDkgAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 30; attempt++)
        {
            try
            {
                using var response = await ProbeClient
                    .GetAsync("http://127.0.0.1:9700/api/graph-status", cancellationToken)
                    .ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    var body = await response.Content
                        .ReadAsStringAsync(cancellationToken)
                        .ConfigureAwait(false);
                    using var document = JsonDocument.Parse(body);
                    var root = document.RootElement;
                    if (root.ValueKind == JsonValueKind.Object &&
                        root.TryGetProperty("node_reachable", out var reachable) &&
                        reachable.ValueKind == JsonValueKind.True &&
                        root.TryGetProperty("dkg_url", out var dkgUrl) &&
                        dkgUrl.ValueKind == JsonValueKind.String &&
                        !string.IsNullOrWhiteSpace(dkgUrl.GetString()))
                    {
                        return true;
                    }
                }
            }
            catch (Exception exception) when (exception is HttpRequestException or JsonException)
            {
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
            }

            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
        }

        return false;
    }

    private static void CleanupLegacyInstall()
    {
        try
        {
            var legacyDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Programs",
                "Netpetra");
            if (Directory.Exists(legacyDir))
            {
                foreach (var file in new[] { "Netpetra.Desktop.exe", "Netpetra.Service.exe", "install.json", "Axiom.Desktop.exe", "Axiom.Service.exe" })
                {
                    var path = Path.Combine(legacyDir, file);
                    if (File.Exists(path))
                    {
                        File.Delete(path);
                    }
                }

                var community = Path.Combine(legacyDir, "community");
                if (Directory.Exists(community))
                {
                    var entries = Directory.EnumerateFileSystemEntries(community).ToArray();
                    if (entries.Length == 0 ||
                        (entries.Length == 1 && string.Equals(Path.GetFileName(entries[0]), "feed.json", StringComparison.OrdinalIgnoreCase)))
                    {
                        Directory.Delete(community, recursive: true);
                    }
                }

                if (!Directory.EnumerateFileSystemEntries(legacyDir).Any())
                {
                    Directory.Delete(legacyDir);
                }
            }

            var shortcuts = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft",
                "Windows",
                "Start Menu",
                "Programs");
            var legacyShortcut = Path.Combine(shortcuts, "Netpetra.lnk");
            if (File.Exists(legacyShortcut))
            {
                File.Delete(legacyShortcut);
            }

            using var run = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                writable: true);
            run?.DeleteValue("Netpetra", throwOnMissingValue: false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
        }
    }

    private static bool CreateStartMenuShortcut(string target, string workingDirectory)
    {
        object? shell = null;
        object? shortcut = null;
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType is null)
            {
                return false;
            }

            shell = Activator.CreateInstance(shellType);
            if (shell is null)
            {
                return false;
            }

            var shortcutPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft",
                "Windows",
                "Start Menu",
                "Programs",
                "Axiom.lnk");
            Directory.CreateDirectory(Path.GetDirectoryName(shortcutPath)!);

            shortcut = shellType.InvokeMember(
                "CreateShortcut",
                BindingFlags.InvokeMethod,
                binder: null,
                shell,
                [shortcutPath],
                CultureInfo.InvariantCulture);

            if (shortcut is null)
            {
                return false;
            }

            var shortcutType = shortcut.GetType();
            shortcutType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, [target],
                CultureInfo.InvariantCulture);
            shortcutType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, [workingDirectory],
                CultureInfo.InvariantCulture);
            shortcutType.InvokeMember("Description", BindingFlags.SetProperty, null, shortcut,
                ["Axiom - Free Open-Source Network & AI Agent Security"], CultureInfo.InvariantCulture);
            shortcutType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, null,
                CultureInfo.InvariantCulture);
            return true;
        }
        catch (Exception exception) when (exception is COMException or TargetInvocationException or IOException)
        {
            return false;
        }
        finally
        {
            if (shortcut is not null && Marshal.IsComObject(shortcut))
            {
                Marshal.FinalReleaseComObject(shortcut);
            }

            if (shell is not null && Marshal.IsComObject(shell))
            {
                Marshal.FinalReleaseComObject(shell);
            }
        }
    }

    private static void SaveLastSetupWarning(string? warning)
    {
        try
        {
            var logDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Axiom",
                "logs");
            var path = Path.Combine(logDir, "setup-last-warning.txt");
            if (string.IsNullOrWhiteSpace(warning))
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }

                return;
            }

            Directory.CreateDirectory(logDir);
            File.WriteAllText(path, warning);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private sealed record PayloadPaths(string? DesktopPath, string? ServicePath, string? CommunityPath)
    {
        public bool HasDesktop => DesktopPath is not null;

        public bool HasService => ServicePath is not null;
    }
}
