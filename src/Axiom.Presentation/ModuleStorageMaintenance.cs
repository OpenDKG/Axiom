// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Axiom.Presentation;

/// <summary>Summary of one maintenance pass for Axiom and Blackbox.</summary>
public sealed record StorageMaintenanceReport(
    int DkgConfigsUpdated,
    int TrimmedLogs,
    int RemovedFiles,
    long ReclaimedBytes);

/// <summary>
/// Applies the vendor's WAL maintenance default to managed Blackbox nodes and retains a bounded
/// set of rotated diagnostic logs. The active graph and protection history remain in their stores.
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
        string? userProfile = null)
    {
        var local = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var home = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var dkgConfigsUpdated = 0;
        var trimmedLogs = 0;
        var removedFiles = 0;
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

        if (!string.IsNullOrWhiteSpace(local))
        {
            TrimIfOversized(
                Path.Combine(local, "Axiom", "tray-error.log"),
                maxBytes: 2L * 1024 * 1024,
                keepBytes: 512L * 1024,
                ref trimmedLogs,
                ref reclaimedBytes);
        }

        return new StorageMaintenanceReport(
            dkgConfigsUpdated,
            trimmedLogs,
            removedFiles,
            reclaimedBytes);
    }

    /// <summary>
    /// Ensures a DKG <c>config.json</c> using the <c>oxigraph-server</c> backend enables DKG's
    /// built-in WAL maintenance reopen (<c>store.options.walRestartThresholdBytes</c>). Preserves
    /// an existing threshold and the rest of the vendor configuration.
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

            if (store["options"] is null)
            {
                store["options"] = new JsonObject();
            }

            if (store["options"] is not JsonObject options ||
                options.ContainsKey("walRestartThresholdBytes"))
            {
                return false;
            }

            options["walRestartThresholdBytes"] = thresholdBytes;
            var tempPath = configPath + ".axiom-tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                File.WriteAllText(tempPath, rootNode.ToJsonString(IndentedJson));
                if (!string.Equals(File.ReadAllText(configPath, Encoding.UTF8), raw, StringComparison.Ordinal))
                {
                    return false;
                }

                File.Move(tempPath, configPath, overwrite: true);
                return true;
            }
            finally
            {
                File.Delete(tempPath);
            }
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
            keepBytes > int.MaxValue ||
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
                FileShare.Read);

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

            var firstNewline = Array.IndexOf(buffer, (byte)'\n', 0, totalRead);
            if (firstNewline < 0 || firstNewline + 1 == totalRead)
            {
                return 0;
            }

            var offset = firstNewline + 1;
            var keptCount = totalRead - offset;            stream.Seek(0, SeekOrigin.Begin);
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

    private static IEnumerable<string> EnumerateDkgHomes(string localAppData, string userProfile)
    {
        if (!string.IsNullOrWhiteSpace(localAppData))
        {
            yield return Path.Combine(localAppData, "hermes", "blackbox", "node", ".dkg");
        }

        if (!string.IsNullOrWhiteSpace(userProfile))
        {
            yield return Path.Combine(userProfile, ".hermes", "blackbox", "node", ".dkg");
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
}
