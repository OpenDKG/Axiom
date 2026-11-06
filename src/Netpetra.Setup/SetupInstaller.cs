// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Netpetra.UI.Services;

namespace Netpetra.Setup;

internal sealed record SetupInstallResult(bool Success, string Message, IReadOnlyList<string> Log);

internal static class SetupInstaller
{
    private const string PayloadPrefix = "Netpetra.Setup.Payload.";

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
        void Report(string message)
        {
            log.Add(message);
            progress?.Report(message);
        }

        try
        {
            if (Process.GetProcessesByName("Netpetra.Desktop").Length > 0 ||
                Process.GetProcessesByName("Netpetra.Service").Length > 0)
            {
                return new SetupInstallResult(false, "Axiom is running. Close it before installing.", log);
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
                Report($"Installing to {options.InstallDir}");

                var desktopTarget = Path.Combine(options.InstallDir, "Netpetra.Desktop.exe");
                var serviceTarget = Path.Combine(options.InstallDir, "Netpetra.Service.exe");
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

                var blackboxInstalled = false;
                var dkgInstalled = false;
                if (options.CompleteInstallation)
                {
                    Report("Complete installation selected: Blackbox, DKG and agent hooks will be configured.");
                    var setupProtection = new UserStateProtection();
                    var setupSnapshot = await Task.Run(
                        () => setupProtection.Capture(),
                        cancellationToken).ConfigureAwait(false);
                    var moduleInstaller = new OptionalModuleInstaller();

                    Report("Auditing official installer scope: Axiom modules, Hermes plugin config/mode and scheduled task only.");
                    Report("Starting the official Blackbox installer. Follow its prompts and terms.");
                    var blackboxExit = await Task.Run(
                        () => moduleInstaller.InstallBlackboxAndWait(Report),
                        cancellationToken).ConfigureAwait(false);
                    Report($"Blackbox installer exit code: {(blackboxExit ? "0" : "non-zero")}.");

                    Report("Starting the official DKG installer. Follow its prompts and terms.");
                    var dkgExit = await Task.Run(
                        () => moduleInstaller.InstallDkgAndWait(Report),
                        cancellationToken).ConfigureAwait(false);
                    Report($"DKG installer exit code: {(dkgExit ? "0" : "non-zero")}.");

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
                            return new SetupInstallResult(
                                false,
                                "Optional setup stopped: a protected user-state change could not be restored.",
                                log);
                        }
                    }
                    else
                    {
                        Report("Protected user-state check: MCP servers, models, favorites, sessions and Antigravity/Gemini history were unchanged.");
                    }

                    blackboxInstalled = await WaitForEndpointAsync(
                        "http://127.0.0.1:9700/api/graph-status", cancellationToken).ConfigureAwait(false);
                    dkgInstalled = await WaitForEndpointAsync(
                        "http://127.0.0.1:9200/api/status", cancellationToken).ConfigureAwait(false);
                    Report($"Blackbox endpoint: {(blackboxInstalled ? "connected" : "not verified")}; " +
                           $"DKG endpoint: {(dkgInstalled ? "connected" : "not verified")}.");

                    Report("Installing agent hooks after the Blackbox runtime is prepared.");
                    var protection = new UserStateProtection();
                    var protectedBefore = await Task.Run(
                        () => protection.Capture(),
                        cancellationToken).ConfigureAwait(false);
                    var openCodeProtection = new OpenCodeProtection();
                    var codexProtection = new CodexProtection();
                    var claudeProtection = new ClaudeProtection();
                    var cursorProtection = new CursorProtection();
                    var copilotProtection = new CopilotProtection();
                    var geminiProtection = new GeminiProtection();
                    var windsurfProtection = new WindsurfProtection();
                    var clineProtection = new ClineProtection();
                    var openCode = openCodeProtection.EnsureInstalled();
                    var codex = codexProtection.EnsureInstalled();
                    var claude = claudeProtection.EnsureInstalled();
                    var cursor = cursorProtection.EnsureInstalled();
                    var copilot = copilotProtection.EnsureInstalled();
                    var gemini = geminiProtection.EnsureInstalled();
                    var windsurf = windsurfProtection.EnsureInstalled();
                    var cline = clineProtection.EnsureInstalled();
                    var unexpectedChanges = await Task.Run(
                        () => protection.Verify(
                            protectedBefore,
                            [
                                openCodeProtection.PluginPath,
                                openCodeProtection.V1PluginPath,
                                openCodeProtection.LegacyPluginPath,
                                openCodeProtection.BridgePath,
                                codexProtection.HooksPath,
                                codexProtection.HookScriptPath,
                                claudeProtection.SettingsPath,
                                claudeProtection.HookScriptPath,
                                cursorProtection.HooksPath,
                                cursorProtection.HookScriptPath,
                                copilotProtection.HooksPath,
                                copilotProtection.HookScriptPath,
                                geminiProtection.SettingsPath,
                                geminiProtection.HookScriptPath,
                                windsurfProtection.HooksPath,
                                windsurfProtection.HookScriptPath,
                                clineProtection.HookPath,
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
                            return new SetupInstallResult(
                                false,
                                "Agent hook setup stopped: a protected user-state change could not be restored.",
                                log);
                        }
                    }
                    else
                    {
                        Report("Agent hooks: MCP server definitions, selected models, favorites, sessions and Antigravity history were not changed.");
                    }

                    Report($"Agent hooks: OpenCode/OpenChamber {(openCode ? "installed" : "skipped")}, " +
                           $"Codex {(codex ? "installed" : "skipped")}, Claude Code {(claude ? "installed" : "skipped")}, " +
                           $"Cursor {(cursor ? "installed" : "skipped")}, " +
                           $"GitHub Copilot CLI {(copilot ? "installed" : "skipped")}, Gemini CLI {(gemini ? "installed" : "skipped")}, " +
                           $"Windsurf Cascade {(windsurf ? "installed" : "skipped")}, Cline {(cline ? "installed" : "skipped")}.");
                }
                else
                {
                    Report("Partial installation selected: no Blackbox, DKG or agent hook files were changed.");
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

                if (options.StartAfterInstall)
                {
                    Process.Start(new ProcessStartInfo(desktopTarget)
                    {
                        UseShellExecute = true,
                        WorkingDirectory = options.InstallDir,
                    });
                    Report("Started Axiom");
                }

                return new SetupInstallResult(true, "Axiom was installed successfully.", log);
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

    private static async Task<PayloadPaths> ExtractPayloadAsync(
        string tempDir,
        Action<string> report,
        CancellationToken cancellationToken)
    {
        var desktop = await ExtractResourceAsync(
            PayloadPrefix + "Netpetra.Desktop.exe",
            Path.Combine(tempDir, "Netpetra.Desktop.exe"),
            cancellationToken).ConfigureAwait(false);
        var service = await ExtractResourceAsync(
            PayloadPrefix + "Netpetra.Service.exe",
            Path.Combine(tempDir, "Netpetra.Service.exe"),
            cancellationToken).ConfigureAwait(false);
        var community = await ExtractResourceAsync(
            PayloadPrefix + "community.feed.json",
            Path.Combine(tempDir, "community", "feed.json"),
            cancellationToken).ConfigureAwait(false);

        if (desktop is null || service is null)
        {
            report("Embedded payload not found; looking for release files next to setup.");
            desktop ??= ExistingOrNull(Path.Combine(AppContext.BaseDirectory, "Netpetra.Desktop.exe"));
            service ??= ExistingOrNull(Path.Combine(AppContext.BaseDirectory, "Netpetra.Service.exe"));
            community ??= ExistingOrNull(Path.Combine(AppContext.BaseDirectory, "community", "feed.json"));
        }

        return new PayloadPaths(desktop, service, community);
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

    private static void CopyFile(string source, string destination, bool overwrite) =>
        File.Copy(source, destination, overwrite);

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
                ["Axiom - Open-Source Firewall & Security Monitor"], CultureInfo.InvariantCulture);
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

    private sealed record PayloadPaths(string? DesktopPath, string? ServicePath, string? CommunityPath)
    {
        public bool HasDesktop => DesktopPath is not null;

        public bool HasService => ServicePath is not null;
    }
}
