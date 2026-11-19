// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text.Json;
using Axiom.Contracts.Community;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Privacy;
using Axiom.Contracts.Protection;
using Axiom.Presentation;
using Microsoft.Win32;

namespace Axiom.Setup;

internal sealed record CompleteDefaultsResult(bool Applied, string? Warning);

/// <summary>
/// Applies the complete-installation protection profile: registers the elevated service, turns on
/// Axiom Shield and the Privacy Shield resolver, enables notifications/tray/background-window
/// hiding and per-user autostart. Partial installation never calls this type.
/// </summary>
internal static class SetupDefaults
{
    public const string ProfileFileName = "install-profile.json";

    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

    private const string AutostartValueName = "Axiom";

    private static readonly JsonSerializerOptions ProfileJsonOptions = new()
    {
        WriteIndented = true,
    };

    private static readonly JsonSerializerOptions WebJsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static bool EnsureServiceRegistered(string installDir, Action<string> report)
    {
        report("Complete protection: registering the Axiom Windows service (one elevation prompt).");
        return InstallService(installDir, report);
    }

    public static async Task<CompleteDefaultsResult> ApplyCompleteAsync(
        string installDir,
        Action<string> report,
        CancellationToken cancellationToken,
        bool serviceAlreadyRegistered = false,
        bool allowManualThreatSharing = false)
    {
        var marker = new Dictionary<string, object?>
        {
            ["profile"] = "complete",
            ["startedUtc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
            ["serviceInstalled"] = false,
            ["shieldEnabled"] = false,
            ["privacyEnabled"] = false,
        };

        if (allowManualThreatSharing && !ThreatSharingConsent.TrySetPermission(true))
        {
            report("The manual threat-reporting preference could not be saved. Review it in Agent Protection.");
        }

        try
        {
            var serviceInstalled = serviceAlreadyRegistered;
            if (!serviceInstalled)
            {
                report("Complete protection: registering the Axiom Windows service (one elevation prompt).");
                serviceInstalled = InstallService(installDir, report);
            }

            if (!serviceInstalled)
            {
                marker["appliedUtc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
                WriteProfile(marker);
                return new CompleteDefaultsResult(
                    false,
                    "Axiom was installed, but complete protection defaults were not applied.\n\n" +
                    "The Windows service was not registered (elevation was cancelled or failed). " +
                    "You can enable Axiom Shield later from the Firewall page; it will ask once.");
            }

            marker["serviceInstalled"] = true;
            StopInteractiveServiceProcesses(report);

            var client = new IpcPipeClient(
                connectTimeout: TimeSpan.FromSeconds(2),
                requestTimeout: TimeSpan.FromMinutes(5));

            if (!await WaitForServiceAsync(client, report, cancellationToken).ConfigureAwait(false))
            {
                marker["appliedUtc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
                WriteProfile(marker);
                return new CompleteDefaultsResult(
                    false,
                    "Axiom was installed and the service registered, but the local service did not " +
                    "answer in time. Open Axiom and check the Firewall page.");
            }

            try
            {
                var shield = await client
                    .SendAsync<ProtectionStatus>(
                        IpcCommandTypes.ProtectionEnable,
                        new ProtectionEnableRequest(),
                        cancellationToken)
                    .ConfigureAwait(false);
                marker["shieldEnabled"] = shield.Enabled;
                report(shield.Enabled
                    ? "Axiom Shield: enabled (default policy: ask)."
                    : "Axiom Shield: the service kept it disabled; check the Firewall page.");
            }
            catch (Exception exception) when (exception is IpcClientException or IOException)
            {
                report("Axiom Shield could not be enabled: " + exception.Message);
            }

            var privacySettings = new PrivacyShieldSettings
            {
                Enabled = true,
                Profile = PrivacyShieldProfile.Strict,
                Categories = PrivacyShieldCategories.ForProfile(PrivacyShieldProfile.Strict)
                             | PrivacyCategory.Custom,
                Port = 53,
                UpstreamDns = PrivacyShieldPolicy.DefaultDohUpstream,
                EncryptDnsViaDoh = true,
                EnabledSourceIds = PrivacyShieldSourceCatalog.All.Select(source => source.Id).ToArray(),
                LogQueries = false,
                AutoPointAdapterDns = true,
                AutoUpdateSources = true,
                AutoUpdateIntervalHours = 24,
            };

            try
            {
                var privacy = await client
                    .SendAsync<PrivacyShieldStatus>(
                        IpcCommandTypes.PrivacyConfigure,
                        privacySettings,
                        cancellationToken)
                    .ConfigureAwait(false);
                marker["privacyEnabled"] = privacy.Enabled && privacy.Running;
                report(privacy.Running
                    ? $"Privacy Shield: resolver enabled on port 53 (Strict, all {privacySettings.EnabledSourceIds.Count} sources selected)."
                    : "Privacy Shield: enabled, but the resolver is not running yet: " + privacy.Detail);
                if (!string.IsNullOrWhiteSpace(privacy.LastError))
                {
                    report("Privacy Shield adapter DNS: " + privacy.LastError);
                }
                else if (privacy.Running && privacy.Settings.AutoPointAdapterDns)
                {
                    report("Privacy Shield: active adapter DNS points at 127.0.0.1 with fallback DNS preserved.");
                }

                if (privacy.Running)
                {
                    try
                    {
                        report($"Privacy Shield: downloading and compiling all {privacySettings.EnabledSourceIds.Count} blocklist sources...");
                        var updated = await client
                            .SendAsync<PrivacyShieldStatus>(
                                IpcCommandTypes.PrivacySourcesUpdate,
                                null,
                                cancellationToken)
                            .ConfigureAwait(false);
                        var entries = updated.Sources.Sum(source => source.Entries);
                        marker["privacyEntries"] = entries;
                        report(updated.LastError is { Length: > 0 } error
                            ? "Privacy Shield blocklists: " + error
                            : $"Privacy Shield blocklists: {entries:N0} entries compiled.");
                    }
                    catch (Exception exception) when (exception is IpcClientException or IOException)
                    {
                        report("Privacy Shield blocklists could not be downloaded; starter rules remain: " +
                               exception.Message);
                    }
                }
            }
            catch (Exception exception) when (exception is IpcClientException or IOException)
            {
                report("Privacy Shield could not be enabled: " + exception.Message);
            }

            WriteUserDefaults(installDir, privacySettings, report);
            marker["appliedUtc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
            WriteProfile(marker);

            var complete = marker["shieldEnabled"] is true && marker["privacyEnabled"] is true;
            report(complete
                ? "Complete protection defaults applied: Shield on, Privacy Shield resolver on, notifications and autostart on."
                : "Complete protection defaults were partially applied. Review Shield and Privacy Shield in Axiom.");

            return new CompleteDefaultsResult(
                complete,
                complete
                    ? null
                    : "Axiom was installed, but one or more protection defaults could not be enabled. " +
                      "Open Axiom and check the Firewall and Privacy Shield pages.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                              System.Security.SecurityException or InvalidOperationException)
        {
            report("Complete protection defaults failed: " + exception.Message);
            marker["appliedUtc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
            WriteProfile(marker);
            return new CompleteDefaultsResult(
                false,
                "Axiom was installed, but complete protection defaults failed: " + exception.Message);
        }
    }

    public static void WritePartialProfile()
    {
        WriteProfile(new Dictionary<string, object?>
        {
            ["profile"] = "partial",
            ["appliedUtc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
            ["serviceInstalled"] = false,
            ["shieldEnabled"] = false,
            ["privacyEnabled"] = false,
        });
    }

    private static bool InstallService(string installDir, Action<string> report)
    {
        var executable = Path.Combine(installDir, "Axiom.Service.exe");
        if (!File.Exists(executable))
        {
            report("Axiom.Service.exe is missing from the install directory.");
            return false;
        }

        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = executable,
                Arguments = "--install-service",
                UseShellExecute = true,
                Verb = "runas",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            });

            if (process is null)
            {
                report("The elevated service installer did not start.");
                return false;
            }

            if (!process.WaitForExit(180_000))
            {
                report("The elevated service installer did not finish within three minutes.");
                return false;
            }

            if (process.ExitCode == 0)
            {
                report("Axiom service registered and started.");
                return true;
            }

            report($"The elevated service installer exited with code {process.ExitCode}.");
            // The elevated process runs with runas, so its stderr is not ours to read; it writes its
            // own step log instead, and the reason belongs in the setup log (issue #367).
            foreach (var line in ServiceInstallLog.Tail(8))
            {
                report("  service: " + line);
            }

            return false;
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            report("Administrator approval was cancelled; protection defaults were not applied.");
            return false;
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException)
        {
            report("The service installer could not start: " + exception.Message);
            return false;
        }
    }

    private static async Task<bool> WaitForServiceAsync(
        IpcPipeClient client,
        Action<string> report,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 30; attempt++)
        {
            try
            {
                _ = await client
                    .SendAsync<ServiceHealth>(IpcCommandTypes.ServiceHealth, null, cancellationToken)
                    .ConfigureAwait(false);
                report("Axiom service pipe is reachable.");
                return true;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (exception is IpcClientException or IOException or TimeoutException)
            {
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
            }
        }

        return false;
    }

    private static void StopInteractiveServiceProcesses(Action<string> report)
    {
        var sessionId = Process.GetCurrentProcess().SessionId;
        foreach (var process in Process.GetProcessesByName("Axiom.Service"))
        {
            try
            {
                if (process.SessionId != sessionId)
                {
                    continue;
                }

                process.Kill(entireProcessTree: true);
                process.WaitForExit(3000);
                report("Stopped the interactive service copy so the Windows service owns the pipe.");
            }
#pragma warning disable CA1031 // Best effort; the pipe reconnect handles the rest.
            catch (Exception)
#pragma warning restore CA1031
            {
            }
            finally
            {
                process.Dispose();
            }
        }
    }

    private static void WriteUserDefaults(
        string installDir,
        PrivacyShieldSettings privacySettings,
        Action<string> report)
    {
        try
        {
            var directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Axiom");
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "notifications.txt"), "enabled");
            File.WriteAllText(Path.Combine(directory, "tray-notifications.txt"), "enabled");
            File.WriteAllText(Path.Combine(directory, "hide-background-windows.txt"), "enabled");
            File.WriteAllText(
                Path.Combine(directory, "privacy-shield.json"),
                JsonSerializer.Serialize(privacySettings, WebJsonOptions));
            File.WriteAllText(
                Path.Combine(directory, "community-feed.json"),
                JsonSerializer.Serialize(
                    new
                    {
                        enabled = true,
                        url = CommunityFeedCatalog.RecommendedBundleUrl,
                        autoSync = true,
                        tokenProtected = string.Empty,
                    },
                    WebJsonOptions));

            var desktop = Path.Combine(installDir, "Axiom.Desktop.exe");
            File.WriteAllText(
                Path.Combine(directory, "startup.json"),
                JsonSerializer.Serialize(new
                {
                    startWithWindows = true,
                    startMinimized = true,
                    lastKnownExecutablePath = desktop,
                    updatedUtc = DateTimeOffset.UtcNow,
                }));

            using var key = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true);
            key?.SetValue(AutostartValueName, $"\"{desktop}\" --autostart", RegistryValueKind.String);
            report("Privacy Shield Strict preset, Community Feed bundle, notifications, tray, background-window hiding and start with Windows: enabled.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                              System.Security.SecurityException)
        {
            report("Per-user preferences could not be written: " + exception.Message);
        }
    }

    private static void WriteProfile(Dictionary<string, object?> marker)
    {
        try
        {
            var directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Axiom");
            Directory.CreateDirectory(directory);
            File.WriteAllText(
                Path.Combine(directory, ProfileFileName),
                JsonSerializer.Serialize(marker, ProfileJsonOptions));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The install itself succeeded; the marker is diagnostic only.
        }
    }
}
