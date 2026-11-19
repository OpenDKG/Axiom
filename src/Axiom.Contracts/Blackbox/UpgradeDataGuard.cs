// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text.Json;

namespace Axiom.Contracts.Blackbox;

/// <summary>One copied file, stored relative to the user's local application data.</summary>
public sealed record UpgradeDataEntry(string RelativePath, long Length);

/// <summary>A completed pre-upgrade backup of the data an update must never lose.</summary>
public sealed record UpgradeDataBackup(
    string Directory,
    IReadOnlyList<UpgradeDataEntry> Entries,
    IReadOnlyList<string> Notes)
{
    public long TotalBytes => Entries.Sum(entry => entry.Length);
}

/// <summary>What the post-upgrade check found: what it put back, what shrank, what failed.</summary>
public sealed record UpgradeDataRestoreResult(
    IReadOnlyList<string> Restored,
    IReadOnlyList<string> Shrunk,
    IReadOnlyList<string> Failed)
{
    public bool Ok => Failed.Count == 0;
}

/// <summary>
/// Keeps the findings, threat history and reporter/node identity across an upgrade.
///
/// A complete install re-runs the vendor Blackbox installer. That installer owns its own tree,
/// and Axiom's user-state snapshot deliberately excludes <c>hermes\blackbox</c> as an installer
/// path, so nothing today would notice if an update dropped the findings log, the reporter key or
/// the DKG identity. This guard copies the small, irreplaceable data before the installer runs and
/// restores anything that disappeared or was left empty. It never truncates or rewrites a file that
/// grew, because new findings are the point of keeping history.
/// </summary>
public static class UpgradeDataGuard
{
    /// <summary>How many timestamped backups stay on disk.</summary>
    public const int KeepBackups = 3;

    private const string ManifestName = "manifest.json";
    private const string ReportName = "guard-report.json";

    /// <summary>Rebuildable rule data, not history. Excluded to keep the backup small.</summary>
    private static readonly string[] SkipNames = ["privacy-shield-rules.json"];

    /// <summary>
    /// Rebuildable or very large vendor data that must not be copied on every upgrade: the
    /// Oxigraph store/logs, node_modules and Python venvs. A lab upgrade copied 8.3 GB / 116k
    /// files and froze the machine because these were included.
    /// </summary>
    private static readonly string[] SkipDirectories =
        ["oxigraph-data", "node_modules", "venv", ".git", "__pycache__", "cache"];

    private static readonly string[] SkipExtensions = [".log", ".tmp", ".etl"];

    /// <summary>Individual files above this size are regenerable data, not findings or identity.</summary>
    private const long MaxFileBytes = 32L * 1024 * 1024;

    private static readonly string[] AxiomTopLevelPatterns = ["*.json", "*.jsonl", "*.db", "*.db-wal", "*.db-shm"];

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    /// <summary>
    /// Copies the Blackbox data, the Axiom history files and the DKG identity to a timestamped
    /// folder. Returns null when there is nothing to protect (a first install).
    /// </summary>
    public static UpgradeDataBackup? Capture(
        string? localAppData = null,
        string? backupRoot = null,
        DateTimeOffset? now = null)
    {
        var local = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var root = backupRoot ?? Path.Combine(local, "Axiom", "backups");
        var sources = Collect(local);
        if (sources.Count == 0)
        {
            return null;
        }

        var stamp = (now ?? DateTimeOffset.UtcNow).ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture);
        var directory = Path.Combine(root, "upgrade-" + stamp);
        Directory.CreateDirectory(directory);

        var entries = new List<UpgradeDataEntry>();
        var notes = new List<string>();
        foreach (var source in sources)
        {
            var relative = Path.GetRelativePath(local, source);
            var target = Path.Combine(directory, relative);
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.Copy(source, target, overwrite: true);
                entries.Add(new UpgradeDataEntry(relative, new FileInfo(target).Length));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                notes.Add($"skipped {relative}: {exception.GetType().Name}");
            }
        }

        if (entries.Count == 0)
        {
            TryDelete(directory);
            return null;
        }

        var manifest = new BackupManifest((now ?? DateTimeOffset.UtcNow), entries);
        File.WriteAllText(Path.Combine(directory, ManifestName), JsonSerializer.Serialize(manifest, JsonOptions));
        Prune(root);
        return new UpgradeDataBackup(directory, entries, notes);
    }

    /// <summary>
    /// Restores every backed-up file that is gone or empty. A file that shrank is reported but left
    /// alone; a file that grew is left alone. Writes <c>guard-report.json</c> next to the backup.
    /// </summary>
    public static UpgradeDataRestoreResult VerifyAndRestore(string backupDirectory, string? localAppData = null)
    {
        var local = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var restored = new List<string>();
        var shrunk = new List<string>();
        var failed = new List<string>();

        var manifestPath = Path.Combine(backupDirectory, ManifestName);
        if (!File.Exists(manifestPath))
        {
            failed.Add("the backup manifest is missing");
            return new UpgradeDataRestoreResult(restored, shrunk, failed);
        }

        BackupManifest? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<BackupManifest>(File.ReadAllText(manifestPath), JsonOptions);
        }
        catch (JsonException)
        {
            failed.Add("the backup manifest is unreadable");
            return new UpgradeDataRestoreResult(restored, shrunk, failed);
        }

        if (manifest is null)
        {
            failed.Add("the backup manifest is empty");
            return new UpgradeDataRestoreResult(restored, shrunk, failed);
        }

        var normalizedBackupRoot = EnsureTrailingSeparator(Path.GetFullPath(backupDirectory));
        var normalizedLocalRoot = EnsureTrailingSeparator(Path.GetFullPath(local));

        foreach (var entry in manifest.Entries)
        {
            var relativePath = entry.RelativePath;
            if (string.IsNullOrWhiteSpace(relativePath) ||
                !TryResolveContainedPath(backupDirectory, normalizedBackupRoot, relativePath, out var source) ||
                !TryResolveContainedPath(local, normalizedLocalRoot, relativePath, out var target))
            {
                failed.Add(relativePath ?? string.Empty);
                continue;
            }

            if (!File.Exists(source))
            {
                failed.Add(relativePath);
                continue;
            }

            var current = File.Exists(target) ? new FileInfo(target).Length : -1;
            if (current > 0)
            {
                if (current < entry.Length)
                {
                    shrunk.Add(relativePath);
                }

                continue;
            }

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.Copy(source, target, overwrite: true);
                restored.Add(relativePath);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                failed.Add(relativePath);
            }
        }

        var report = new
        {
            checkedUtc = DateTimeOffset.UtcNow,
            restored,
            shrunk,
            failed,
        };
        try
        {
            File.WriteAllText(Path.Combine(backupDirectory, ReportName), JsonSerializer.Serialize(report, JsonOptions));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The report is diagnostic; a read-only backup folder must not fail the restore.
        }

        return new UpgradeDataRestoreResult(restored, shrunk, failed);
    }

    /// <summary>Removes old upgrade backups, keeping the newest <paramref name="keep"/>.</summary>
    public static IReadOnlyList<string> Prune(string backupRoot, int keep = KeepBackups)
    {
        var removed = new List<string>();
        if (!Directory.Exists(backupRoot))
        {
            return removed;
        }

        List<string> directories;
        try
        {
            directories = Directory.GetDirectories(backupRoot, "upgrade-*")
                .OrderByDescending(path => Path.GetFileName(path), StringComparer.Ordinal)
                .ToList();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return removed;
        }

        foreach (var directory in directories.Skip(Math.Max(1, keep)))
        {
            if (TryDelete(directory))
            {
                removed.Add(directory);
            }
        }

        return removed;
    }

    private static List<string> Collect(string local)
    {
        var files = new List<string>();

        var blackbox = Path.Combine(local, "hermes", "blackbox");
        if (Directory.Exists(blackbox))
        {
            files.AddRange(Enumerate(blackbox, "*", SearchOption.AllDirectories));
        }

        var hermesConfig = Path.Combine(local, "hermes", "config.yaml");
        if (File.Exists(hermesConfig))
        {
            files.Add(hermesConfig);
        }

        var axiom = Path.Combine(local, "Axiom");
        if (Directory.Exists(axiom))
        {
            foreach (var pattern in AxiomTopLevelPatterns)
            {
                files.AddRange(Enumerate(axiom, pattern, SearchOption.TopDirectoryOnly));
            }
        }

        // Every DKG home an install can leave behind: the bundled Blackbox home, Axiom's optional
        // standalone home, and the managed path. Backing up only one of them loses the node
        // identity and the local graph as soon as the install layout changes.
        foreach (var dkg in DkgHomeResolver.CandidateHomes(local))
        {
            if (Directory.Exists(dkg))
            {
                files.AddRange(Enumerate(dkg, "*", SearchOption.AllDirectories));
            }
        }

        return files
            .Where(path => !SkipNames.Contains(Path.GetFileName(path), StringComparer.OrdinalIgnoreCase))
            .Where(path => !SkipExtensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase))
            .Where(path => !InSkippedDirectory(path))
            .Where(path => FileSize(path) <= MaxFileBytes)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static bool InSkippedDirectory(string path)
    {
        foreach (var segment in path.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (Array.Exists(SkipDirectories, name => string.Equals(name, segment, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    private static long FileSize(string path)
    {
        try
        {
            return new FileInfo(path).Length;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return long.MaxValue;
        }
    }

    private static string[] Enumerate(string path, string pattern, SearchOption option)
    {
        try
        {
            return Directory.EnumerateFiles(path, pattern, option).ToArray();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static bool TryDelete(string directory)
    {
        try
        {
            Directory.Delete(directory, recursive: true);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string EnsureTrailingSeparator(string fullPath) =>
        fullPath.EndsWith(Path.DirectorySeparatorChar) || fullPath.EndsWith(Path.AltDirectorySeparatorChar)
            ? fullPath
            : fullPath + Path.DirectorySeparatorChar;

    private static bool TryResolveContainedPath(
        string root,
        string normalizedRoot,
        string? relativePath,
        out string fullPath)
    {
        fullPath = string.Empty;
        if (string.IsNullOrWhiteSpace(relativePath) || Path.IsPathRooted(relativePath))
        {
            return false;
        }

        try
        {
            var candidate = Path.GetFullPath(Path.Combine(root, relativePath));
            if (!candidate.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            fullPath = candidate;
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private sealed record BackupManifest(DateTimeOffset CreatedUtc, IReadOnlyList<UpgradeDataEntry> Entries);
}
