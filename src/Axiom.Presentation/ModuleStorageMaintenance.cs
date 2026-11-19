// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiom.Contracts.Blackbox;

namespace Axiom.Presentation;

/// <summary>Summary of one bounded storage-maintenance pass across Axiom, Hermes, Blackbox and DKG.</summary>
public sealed record StorageMaintenanceReport(
    int DkgConfigsUpdated,
    int TrimmedLogs,
    int RemovedFiles,
    int RemovedDirectories,
    long ReclaimedBytes);

/// <summary>
/// Keeps optional-module and Axiom disk usage bounded without removing active data, keys, findings
/// history or live database files:
/// <list type="bullet">
///   <item>Enables DKG's official opt-in Oxigraph WAL reopen (<c>walRestartThresholdBytes</c>) so RocksDB WAL files do not grow unbounded.</item>
///   <item>Prunes rotated RocksDB diagnostic text logs (<c>LOG.old.*</c>) while leaving active RocksDB data untouched.</item>
///   <item>Prunes orphaned Hermes Python environments not referenced by <c>facts.json</c> (skipping anything recently modified).</item>
///   <item>Trims oversized append-only logs (<c>agent.log</c>, <c>errors.log</c>, <c>audit.jsonl</c>, etc.) in place on newline boundaries.</item>
///   <item>Caps rotated DKG <c>daemon.log.&lt;N&gt;</c> copies and cleans stale temporary files and legacy service backups.</item>
/// </list>
/// </summary>
public static class ModuleStorageMaintenance
{
    /// <summary>Default Oxigraph WAL reopen threshold (512 MiB) written into managed DKG configs.</summary>
    public const long DefaultOxigraphWalRestartThresholdBytes = 512L * 1024 * 1024;

    /// <summary>Number of rotated RocksDB diagnostic <c>LOG.old.*</c> text files retained.</summary>
    public const int KeepOxigraphOldInfoLogs = 10;

    /// <summary>Number of rotated DKG <c>daemon.log.&lt;N&gt;</c> files retained alongside the live file.</summary>
    public const int KeepDkgRotatedLogs = 2;

    private static readonly TimeSpan PeriodicInitialDelay = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan PeriodicInterval = TimeSpan.FromHours(6);
    private static readonly TimeSpan DefaultMinOrphanEnvAge = TimeSpan.FromHours(1);
    private static readonly TimeSpan DefaultMinOrphanInstallAge = TimeSpan.FromHours(24);
    private static readonly TimeSpan DefaultMinStaleArtifactAge = TimeSpan.FromHours(24);

    private static readonly JsonSerializerOptions IndentedJson = new() { WriteIndented = true };

    private static int _running;

    /// <summary>
    /// Starts a lightweight background timer that runs maintenance shortly after startup and every
    /// six hours thereafter. Failures are swallowed so storage cleanup never disrupts protection.
    /// </summary>
    public static IDisposable StartPeriodic(
        TimeSpan? initialDelay = null,
        TimeSpan? interval = null)
    {
        var due = initialDelay ?? PeriodicInitialDelay;
        var period = interval ?? PeriodicInterval;
        return new Timer(
            static _ =>
            {
                if (Interlocked.Exchange(ref _running, 1) != 0)
                {
                    return;
                }

                try
                {
                    _ = RunOnce();
                }
#pragma warning disable CA1031 // Storage maintenance is best-effort background hygiene.
                catch (Exception)
#pragma warning restore CA1031
                {
                }
                finally
                {
                    Volatile.Write(ref _running, 0);
                }
            },
            state: null,
            dueTime: due,
            period: period);
    }

    /// <summary>Runs one complete, fail-safe storage-maintenance pass.</summary>
    public static StorageMaintenanceReport RunOnce(
        string? localAppData = null,
        string? userProfile = null,
        DateTimeOffset? nowUtc = null,
        TimeSpan? minOrphanEnvAge = null,
        TimeSpan? minOrphanInstallAge = null,
        TimeSpan? minStaleArtifactAge = null)
    {
        var local = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var home = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        var envAge = minOrphanEnvAge ?? DefaultMinOrphanEnvAge;
        var installAge = minOrphanInstallAge ?? DefaultMinOrphanInstallAge;
        var artifactAge = minStaleArtifactAge ?? DefaultMinStaleArtifactAge;

        var dkgConfigsUpdated = 0;
        var trimmedLogs = 0;
        var removedFiles = 0;
        var removedDirectories = 0;
        long reclaimedBytes = 0;

        foreach (var dkgHome in EnumerateDkgHomes(local, home))
        {
            if (EnsureOxigraphWalMaintenance(Path.Combine(dkgHome, "config.json")))
            {
                dkgConfigsUpdated++;
            }

            PruneOxigraphInfoLogs(
                Path.Combine(dkgHome, "oxigraph-data"),
                KeepOxigraphOldInfoLogs,
                ref removedFiles,
                ref reclaimedBytes);

            PruneDkgRotatedLogs(
                dkgHome,
                KeepDkgRotatedLogs,
                ref removedFiles,
                ref reclaimedBytes);

            TrimIfOversized(
                Path.Combine(dkgHome, "start-console.log"),
                maxBytes: 5L * 1024 * 1024,
                keepBytes: 1L * 1024 * 1024,
                ref trimmedLogs,
                ref reclaimedBytes);
            TrimIfOversized(
                Path.Combine(dkgHome, "start-console.log.err"),
                maxBytes: 5L * 1024 * 1024,
                keepBytes: 1L * 1024 * 1024,
                ref trimmedLogs,
                ref reclaimedBytes);
        }

        foreach (var hermesRoot in EnumerateHermesRoots(local, home))
        {
            PruneOrphanedHermesEnvironments(
                hermesRoot,
                now,
                envAge,
                installAge,
                ref removedDirectories,
                ref reclaimedBytes);

            var logsDir = Path.Combine(hermesRoot, "logs");
            TrimIfOversized(
                Path.Combine(logsDir, "agent.log"),
                maxBytes: 10L * 1024 * 1024,
                keepBytes: 2L * 1024 * 1024,
                ref trimmedLogs,
                ref reclaimedBytes);
            TrimIfOversized(
                Path.Combine(logsDir, "errors.log"),
                maxBytes: 5L * 1024 * 1024,
                keepBytes: 1L * 1024 * 1024,
                ref trimmedLogs,
                ref reclaimedBytes);

            var blackboxDir = Path.Combine(hermesRoot, "blackbox");
            TrimIfOversized(
                Path.Combine(blackboxDir, "audit.jsonl"),
                maxBytes: 15L * 1024 * 1024,
                keepBytes: 5L * 1024 * 1024,
                ref trimmedLogs,
                ref reclaimedBytes);
            TrimIfOversized(
                Path.Combine(blackboxDir, "file_access.jsonl"),
                maxBytes: 10L * 1024 * 1024,
                keepBytes: 3L * 1024 * 1024,
                ref trimmedLogs,
                ref reclaimedBytes);
            TrimIfOversized(
                Path.Combine(blackboxDir, "findings.jsonl"),
                maxBytes: 25L * 1024 * 1024,
                keepBytes: 10L * 1024 * 1024,
                ref trimmedLogs,
                ref reclaimedBytes);

            PruneStaleTempFiles(blackboxDir, now, artifactAge, ref removedFiles, ref reclaimedBytes);
        }

        var axiomDir = ResolveAxiomDataDir(local, home);
        if (!string.IsNullOrWhiteSpace(axiomDir) && Directory.Exists(axiomDir))
        {
            TrimIfOversized(
                Path.Combine(axiomDir, "privacy-shield-blocked.jsonl"),
                maxBytes: 10L * 1024 * 1024,
                keepBytes: 3L * 1024 * 1024,
                ref trimmedLogs,
                ref reclaimedBytes);
            TrimIfOversized(
                Path.Combine(axiomDir, "network-recovery.log"),
                maxBytes: 2L * 1024 * 1024,
                keepBytes: 512L * 1024,
                ref trimmedLogs,
                ref reclaimedBytes);
            TrimIfOversized(
                Path.Combine(axiomDir, "tray-error.log"),
                maxBytes: 2L * 1024 * 1024,
                keepBytes: 512L * 1024,
                ref trimmedLogs,
                ref reclaimedBytes);

            PruneLegacyServiceBackups(axiomDir, now, artifactAge, ref removedFiles, ref reclaimedBytes);
        }

        return new StorageMaintenanceReport(
            dkgConfigsUpdated,
            trimmedLogs,
            removedFiles,
            removedDirectories,
            reclaimedBytes);
    }

    /// <summary>
    /// Ensures a DKG <c>config.json</c> using the <c>oxigraph-server</c> backend enables DKG's
    /// built-in WAL maintenance reopen (<c>store.options.walRestartThresholdBytes</c>). Preserves
    /// any stricter positive threshold already configured by the operator.
    /// </summary>
    public static bool EnsureOxigraphWalMaintenance(
        string configPath,
        long thresholdBytes = DefaultOxigraphWalRestartThresholdBytes)
    {
        if (thresholdBytes <= 0 ||
            string.IsNullOrWhiteSpace(configPath) ||
            !File.Exists(configPath) ||
            StorageSafety.IsReparsePointInPath(configPath))
        {
            return false;
        }

        try
        {
            var raw = File.ReadAllText(configPath, Encoding.UTF8);
            var rootNode = JsonNode.Parse(raw) as JsonObject;
            if (rootNode is null)
            {
                return false;
            }

            if (rootNode["store"] is not JsonObject store)
            {
                return false;
            }

            var backend = store["backend"]?.GetValue<string>();
            if (!string.Equals(backend, "oxigraph-server", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (store["options"] is not JsonObject options)
            {
                options = new JsonObject();
                store["options"] = options;
            }

            if (options["walRestartThresholdBytes"] is JsonValue existingValue &&
                existingValue.TryGetValue<long>(out var existing) &&
                existing > 0 &&
                existing <= thresholdBytes)
            {
                return false;
            }

            options["walRestartThresholdBytes"] = thresholdBytes;

            var updated = rootNode.ToJsonString(IndentedJson);
            var tempPath = configPath + ".axiom-tmp-" + Guid.NewGuid().ToString("N");
            File.WriteAllText(tempPath, updated, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            File.Move(tempPath, configPath, overwrite: true);
            return true;
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>
    /// Trims a growing text or JSONL log file in place when it exceeds <paramref name="maxBytes"/>,
    /// preserving the newest <paramref name="keepBytes"/> aligned to the next newline boundary.
    /// Returns the number of reclaimed bytes, or 0 when no trim occurred.
    /// </summary>
    public static long TrimFileInPlace(string path, long maxBytes, long keepBytes)
    {
        if (maxBytes <= 0 ||
            keepBytes <= 0 ||
            keepBytes >= maxBytes ||
            string.IsNullOrWhiteSpace(path) ||
            !File.Exists(path) ||
            StorageSafety.IsReparsePointInPath(path))
        {
            return 0;
        }

        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length <= maxBytes)
            {
                return 0;
            }

            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.ReadWrite,
                FileShare.ReadWrite | FileShare.Delete);

            var length = stream.Length;
            if (length <= maxBytes)
            {
                return 0;
            }

            var readLength = (int)Math.Min(keepBytes, length);
            var buffer = new byte[readLength];
            stream.Seek(length - readLength, SeekOrigin.Begin);
            var totalRead = 0;
            while (totalRead < readLength)
            {
                var read = stream.Read(buffer, totalRead, readLength - totalRead);
                if (read <= 0)
                {
                    break;
                }

                totalRead += read;
            }

            if (totalRead <= 0)
            {
                return 0;
            }

            var offset = 0;
            var firstNewline = Array.IndexOf(buffer, (byte)'\n', 0, totalRead);
            if (firstNewline >= 0 && firstNewline + 1 < totalRead)
            {
                offset = firstNewline + 1;
            }

            var keptCount = totalRead - offset;
            stream.Seek(0, SeekOrigin.Begin);
            stream.Write(buffer, offset, keptCount);
            stream.Flush();
            stream.SetLength(keptCount);
            return Math.Max(0, length - keptCount);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }

    private static void TrimIfOversized(
        string path,
        long maxBytes,
        long keepBytes,
        ref int trimmedLogs,
        ref long reclaimedBytes)
    {
        var saved = TrimFileInPlace(path, maxBytes, keepBytes);
        if (saved > 0)
        {
            trimmedLogs++;
            reclaimedBytes += saved;
        }
    }

    private static void PruneOxigraphInfoLogs(
        string oxigraphDataDir,
        int keepNewest,
        ref int removedFiles,
        ref long reclaimedBytes)
    {
        if (!Directory.Exists(oxigraphDataDir) || StorageSafety.IsReparsePointInPath(oxigraphDataDir))
        {
            return;
        }

        try
        {
            var oldLogs = new DirectoryInfo(oxigraphDataDir)
                .EnumerateFiles("LOG.old.*", SearchOption.TopDirectoryOnly)
                .Where(file => !StorageSafety.IsReparsePoint(file.FullName))
                .OrderByDescending(file => file.LastWriteTimeUtc)
                .ThenByDescending(file => file.Name, StringComparer.Ordinal)
                .Skip(Math.Max(1, keepNewest))
                .ToArray();

            foreach (var file in oldLogs)
            {
                TryDeleteFile(file, ref removedFiles, ref reclaimedBytes);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static void PruneDkgRotatedLogs(
        string dkgHome,
        int keepRotated,
        ref int removedFiles,
        ref long reclaimedBytes)
    {
        if (!Directory.Exists(dkgHome) || StorageSafety.IsReparsePointInPath(dkgHome))
        {
            return;
        }

        try
        {
            var rotated = new List<(int Index, FileInfo File)>();
            foreach (var file in new DirectoryInfo(dkgHome).EnumerateFiles("daemon.log.*", SearchOption.TopDirectoryOnly))
            {
                if (!file.Name.StartsWith("daemon.log.", StringComparison.OrdinalIgnoreCase) ||
                    StorageSafety.IsReparsePoint(file.FullName))
                {
                    continue;
                }

                var suffix = file.Name.AsSpan("daemon.log.".Length);
                if (int.TryParse(suffix, NumberStyles.None, CultureInfo.InvariantCulture, out var index) &&
                    index > Math.Max(1, keepRotated))
                {
                    rotated.Add((index, file));
                }
            }

            foreach (var (_, file) in rotated.OrderByDescending(entry => entry.Index))
            {
                TryDeleteFile(file, ref removedFiles, ref reclaimedBytes);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static void PruneOrphanedHermesEnvironments(
        string hermesRoot,
        DateTimeOffset nowUtc,
        TimeSpan minOrphanEnvAge,
        TimeSpan minOrphanInstallAge,
        ref int removedDirectories,
        ref long reclaimedBytes)
    {
        var installsDir = Path.Combine(hermesRoot, "installs");
        if (!Directory.Exists(installsDir) || StorageSafety.IsReparsePointInPath(installsDir))
        {
            return;
        }

        DirectoryInfo[] installDirs;
        try
        {
            installDirs = new DirectoryInfo(installsDir)
                .EnumerateDirectories("*", SearchOption.TopDirectoryOnly)
                .Where(dir => !StorageSafety.IsReparsePoint(dir.FullName))
                .ToArray();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return;
        }

        var activeInstalls = new List<(DirectoryInfo Dir, DateTimeOffset FactsUpdatedUtc, string ActiveEnvRoot)>();

        foreach (var installDir in installDirs)
        {
            var activeEnvRoot = ReadActiveHermesEnvironmentRoot(installDir.FullName, out var factsWriteUtc);
            if (activeEnvRoot is null)
            {
                continue;
            }

            activeInstalls.Add((installDir, factsWriteUtc, activeEnvRoot));

            var envsDir = Path.Combine(installDir.FullName, "environments");
            if (!Directory.Exists(envsDir) || StorageSafety.IsReparsePointInPath(envsDir))
            {
                continue;
            }

            DirectoryInfo[] envDirs;
            try
            {
                envDirs = new DirectoryInfo(envsDir)
                    .EnumerateDirectories("*", SearchOption.TopDirectoryOnly)
                    .Where(dir => !StorageSafety.IsReparsePoint(dir.FullName))
                    .ToArray();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var envDir in envDirs)
            {
                if (PathsEqual(envDir.FullName, activeEnvRoot))
                {
                    continue;
                }

                if (nowUtc - envDir.LastWriteTimeUtc < minOrphanEnvAge)
                {
                    continue;
                }

                TryDeleteDirectory(envDir, ref removedDirectories, ref reclaimedBytes);
            }
        }

        if (activeInstalls.Count == 0)
        {
            return;
        }

        // Keep the newest valid install directory (plus any install modified recently); prune older
        // abandoned install trees left behind by previous Hermes layout hashes.
        var newestActive = activeInstalls
            .OrderByDescending(item => item.FactsUpdatedUtc)
            .ThenByDescending(item => item.Dir.LastWriteTimeUtc)
            .First()
            .Dir
            .FullName;

        foreach (var installDir in installDirs)
        {
            if (PathsEqual(installDir.FullName, newestActive))
            {
                continue;
            }

            if (nowUtc - installDir.LastWriteTimeUtc < minOrphanInstallAge)
            {
                continue;
            }

            TryDeleteDirectory(installDir, ref removedDirectories, ref reclaimedBytes);
        }
    }

    private static string? ReadActiveHermesEnvironmentRoot(string installDir, out DateTimeOffset factsWriteUtc)
    {
        factsWriteUtc = DateTimeOffset.MinValue;
        var factsPath = Path.Combine(installDir, "facts.json");
        if (!File.Exists(factsPath) || StorageSafety.IsReparsePoint(factsPath))
        {
            return null;
        }

        try
        {
            factsWriteUtc = File.GetLastWriteTimeUtc(factsPath);
            using var doc = JsonDocument.Parse(File.ReadAllText(factsPath, Encoding.UTF8));
            if (!doc.RootElement.TryGetProperty("packages", out var packages) ||
                packages.ValueKind != JsonValueKind.Object ||
                !packages.TryGetProperty("venv", out var venv) ||
                venv.ValueKind != JsonValueKind.Object ||
                !venv.TryGetProperty("environment", out var envElement) ||
                envElement.ValueKind != JsonValueKind.String)
            {
                return null;
            }

            var envPath = envElement.GetString();
            if (string.IsNullOrWhiteSpace(envPath) || !Directory.Exists(envPath))
            {
                return null;
            }

            var fullEnvPath = Path.GetFullPath(envPath);
            var envsRoot = EnsureTrailingSeparator(Path.GetFullPath(Path.Combine(installDir, "environments")));
            if (!fullEnvPath.StartsWith(envsRoot, PathComparison))
            {
                return null;
            }

            // environment is typically <installDir>/environments/<hash>/venv — resolve the <hash> directory.
            var relative = Path.GetRelativePath(envsRoot, fullEnvPath);
            var firstSegment = relative.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (string.IsNullOrWhiteSpace(firstSegment) || firstSegment is "." or "..")
            {
                return null;
            }

            var activeRoot = Path.GetFullPath(Path.Combine(envsRoot, firstSegment));
            return Directory.Exists(activeRoot) ? activeRoot : null;
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException or ArgumentException)
        {
            return null;
        }
    }

    private static void PruneStaleTempFiles(
        string directory,
        DateTimeOffset nowUtc,
        TimeSpan minAge,
        ref int removedFiles,
        ref long reclaimedBytes)
    {
        if (!Directory.Exists(directory) || StorageSafety.IsReparsePointInPath(directory))
        {
            return;
        }

        try
        {
            foreach (var file in new DirectoryInfo(directory).EnumerateFiles("*.tmp.*", SearchOption.TopDirectoryOnly))
            {
                if (StorageSafety.IsReparsePoint(file.FullName))
                {
                    continue;
                }

                if (nowUtc - file.LastWriteTimeUtc < minAge)
                {
                    continue;
                }

                TryDeleteFile(file, ref removedFiles, ref reclaimedBytes);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static void PruneLegacyServiceBackups(
        string axiomDir,
        DateTimeOffset nowUtc,
        TimeSpan minAge,
        ref int removedFiles,
        ref long reclaimedBytes)
    {
        if (!Directory.Exists(axiomDir) || StorageSafety.IsReparsePointInPath(axiomDir))
        {
            return;
        }

        try
        {
            foreach (var file in new DirectoryInfo(axiomDir).EnumerateFiles("service-backup-*.exe", SearchOption.TopDirectoryOnly))
            {
                if (StorageSafety.IsReparsePoint(file.FullName))
                {
                    continue;
                }

                if (nowUtc - file.LastWriteTimeUtc < minAge)
                {
                    continue;
                }

                TryDeleteFile(file, ref removedFiles, ref reclaimedBytes);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static List<string> EnumerateDkgHomes(string localAppData, string userProfile)
    {
        var seen = new HashSet<string>(PathComparer);
        var homes = new List<string>();

        void AddIfExists(string? candidate)
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                return;
            }

            try
            {
                var full = Path.GetFullPath(candidate);
                if (Directory.Exists(full) && seen.Add(full))
                {
                    homes.Add(full);
                }
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
            {
            }
        }

        if (!string.IsNullOrWhiteSpace(localAppData))
        {
            var effective = DkgHomeResolver.ResolveEffective(
                localAppData,
                ReadFileOrNull,
                Directory.Exists);
            AddIfExists(effective);
            AddIfExists(Path.Combine(localAppData, "hermes", "blackbox", "node", ".dkg"));
            foreach (var candidate in DkgHomeResolver.CandidateHomes(localAppData))
            {
                AddIfExists(candidate);
            }
        }

        if (!string.IsNullOrWhiteSpace(userProfile))
        {
            AddIfExists(Path.Combine(userProfile, ".hermes", "blackbox", "node", ".dkg"));
            AddIfExists(Path.Combine(userProfile, ".dkg"));
        }

        return homes;
    }

    private static List<string> EnumerateHermesRoots(string localAppData, string userProfile)
    {
        var seen = new HashSet<string>(PathComparer);
        var roots = new List<string>();

        void AddIfExists(string? candidate)
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                return;
            }

            try
            {
                var full = Path.GetFullPath(candidate);
                if (Directory.Exists(full) && seen.Add(full))
                {
                    roots.Add(full);
                }
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
            {
            }
        }

        if (!string.IsNullOrWhiteSpace(localAppData))
        {
            AddIfExists(Path.Combine(localAppData, "hermes"));
        }

        if (!string.IsNullOrWhiteSpace(userProfile))
        {
            AddIfExists(Path.Combine(userProfile, ".hermes"));
        }

        return roots;
    }

    private static string? ResolveAxiomDataDir(string localAppData, string userProfile)
    {
        if (!string.IsNullOrWhiteSpace(localAppData))
        {
            var localAxiom = Path.Combine(localAppData, "Axiom");
            if (Directory.Exists(localAxiom))
            {
                return localAxiom;
            }
        }

        if (!string.IsNullOrWhiteSpace(userProfile))
        {
            var xdgAxiom = Path.Combine(userProfile, ".local", "share", "Axiom");
            if (Directory.Exists(xdgAxiom))
            {
                return xdgAxiom;
            }
        }

        return null;
    }

    private static string? ReadFileOrNull(string path)
    {
        try
        {
            return File.Exists(path) ? File.ReadAllText(path, Encoding.UTF8) : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static void TryDeleteFile(FileInfo file, ref int removedFiles, ref long reclaimedBytes)
    {
        try
        {
            var length = file.Length;
            file.Delete();
            removedFiles++;
            reclaimedBytes += length;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static void TryDeleteDirectory(DirectoryInfo directory, ref int removedDirectories, ref long reclaimedBytes)
    {
        try
        {
            var bytes = ComputeDirectorySize(directory);
            directory.Delete(recursive: true);
            removedDirectories++;
            reclaimedBytes += bytes;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static long ComputeDirectorySize(DirectoryInfo directory)
    {
        long total = 0;
        try
        {
            foreach (var file in directory.EnumerateFiles("*", SearchOption.AllDirectories))
            {
                if (!StorageSafety.IsReparsePoint(file.FullName))
                {
                    total += file.Length;
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }

        return total;
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static StringComparer PathComparer =>
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private static bool PathsEqual(string a, string b) =>
        string.Equals(
            Path.GetFullPath(a).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            Path.GetFullPath(b).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            PathComparison);

    private static string EnsureTrailingSeparator(string path) =>
        path.EndsWith(Path.DirectorySeparatorChar) || path.EndsWith(Path.AltDirectorySeparatorChar)
            ? path
            : path + Path.DirectorySeparatorChar;
}
