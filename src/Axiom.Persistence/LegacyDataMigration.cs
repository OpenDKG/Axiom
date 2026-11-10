// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using Axiom.Contracts;

namespace Axiom.Persistence;

/// <summary>
/// One-time migration from the old public name to Axiom. It is the only runtime code allowed to
/// know the old path, database, service, startup and feed names. User data is moved or merged, never
/// discarded because of a failed migration.
/// </summary>
public static class LegacyDataMigration
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

    public static void Migrate(bool stopLegacyProcesses = false)
    {
        if (stopLegacyProcesses)
        {
            StopProcess(LegacyIdentity.ProductName + ".Desktop");
            StopProcess(LegacyIdentity.ProductName + ".Service");
        }

        // The legacy product only shipped on Windows; there is nothing to migrate elsewhere.
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var local = AxiomPaths.UserBaseDirectory;
        var common = AxiomPaths.MachineBaseDirectory;
        MigrateDirectory(
            Path.Combine(local, LegacyIdentity.DataDirectoryName),
            Path.Combine(local, DatabasePaths.DataDirectoryName));
        MigrateDirectory(
            Path.Combine(common, LegacyIdentity.DataDirectoryName),
            Path.Combine(common, DatabasePaths.DataDirectoryName));

        RemoveLegacyAutostart();
    }

    private static void MigrateDirectory(string oldDirectory, string newDirectory)
    {
        if (!Directory.Exists(oldDirectory))
        {
            return;
        }

        try
        {
            if (!Directory.Exists(newDirectory))
            {
                Directory.Move(oldDirectory, newDirectory);
            }
            else
            {
                MergeDirectory(oldDirectory, newDirectory);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A locked database or running agent must not cause data loss. Keep the old tree and
            // retry on the next launch.
            TryLog(newDirectory, exception);
            return;
        }

        RenameDatabaseFiles(newDirectory);
        MigrateStarterFeed(newDirectory);
    }

    private static void MergeDirectory(string source, string destination)
    {
        // Move non-conflicting content into the new tree so the old name disappears after a
        // successful migration. Conflicting files stay in the old tree for manual recovery.
        foreach (var directory in Directory.EnumerateDirectories(source))
        {
            var target = Path.Combine(destination, Path.GetFileName(directory));
            try
            {
                if (!Directory.Exists(target))
                {
                    Directory.Move(directory, target);
                }
                else
                {
                    MergeDirectory(directory, target);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                TryLog(destination, exception);
            }
        }

        foreach (var file in Directory.EnumerateFiles(source))
        {
            var target = Path.Combine(destination, Path.GetFileName(file));
            try
            {
                if (!File.Exists(target))
                {
                    File.Move(file, target);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                TryLog(destination, exception);
            }
        }

        MergeJsonLines(source, destination, "agent-evidence.jsonl");
        MergeJsonLines(source, destination, "privacy-shield-blocked.jsonl");

        try
        {
            if (!Directory.EnumerateFileSystemEntries(source).Any())
            {
                Directory.Delete(source);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            TryLog(destination, exception);
        }
    }

    private static void MergeJsonLines(string sourceDirectory, string destinationDirectory, string fileName)
    {
        var source = Path.Combine(sourceDirectory, fileName);
        var destination = Path.Combine(destinationDirectory, fileName);
        if (!File.Exists(source))
        {
            return;
        }

        try
        {
            var lines = new HashSet<string>(StringComparer.Ordinal);
            if (File.Exists(destination))
            {
                foreach (var line in File.ReadLines(destination))
                {
                    if (!string.IsNullOrWhiteSpace(line))
                    {
                        lines.Add(line);
                    }
                }
            }

            foreach (var line in File.ReadLines(source))
            {
                if (!string.IsNullOrWhiteSpace(line))
                {
                    lines.Add(line);
                }
            }

            File.WriteAllLines(destination, lines.OrderBy(line => line, StringComparer.Ordinal));
            File.Delete(source);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            TryLog(destinationDirectory, exception);
        }
    }

    private static void RenameDatabaseFiles(string directory)
    {
        RenameIfNeeded(
            Path.Combine(directory, LegacyIdentity.DatabaseFileName),
            Path.Combine(directory, DatabasePaths.DatabaseFileName));
        RenameIfNeeded(
            Path.Combine(directory, LegacyIdentity.DatabaseFileName + "-wal"),
            Path.Combine(directory, DatabasePaths.DatabaseFileName + "-wal"));
        RenameIfNeeded(
            Path.Combine(directory, LegacyIdentity.DatabaseFileName + "-shm"),
            Path.Combine(directory, DatabasePaths.DatabaseFileName + "-shm"));
    }

    private static void RenameIfNeeded(string source, string destination)
    {
        if (!File.Exists(source))
        {
            return;
        }

        if (!File.Exists(destination))
        {
            File.Move(source, destination);
        }
    }

    private static void MigrateStarterFeed(string directory)
    {
        var path = Path.Combine(directory, "community-feed.json");
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            var text = File.ReadAllText(path);
            var updated = text.Replace(LegacyIdentity.StarterFeedUrl, "axiom://starter", StringComparison.OrdinalIgnoreCase);
            if (!string.Equals(text, updated, StringComparison.Ordinal))
            {
                File.WriteAllText(path, updated);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            TryLog(directory, exception);
        }
    }

    private static void RemoveLegacyAutostart()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
            key?.DeleteValue(LegacyIdentity.AutostartValueName, throwOnMissingValue: false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
        }
    }

    private static void StopProcess(string processName)
    {
        try
        {
            foreach (var process in Process.GetProcessesByName(processName))
            {
                using (process)
                {
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit(5_000);
                }
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
        }
    }

    private static void TryLog(string directory, Exception exception)
    {
        try
        {
            Directory.CreateDirectory(directory);
            File.AppendAllText(
                Path.Combine(directory, "migration.log"),
                $"{DateTimeOffset.UtcNow:O} {exception.GetType().Name}: {exception.Message}{Environment.NewLine}");
        }
        catch
        {
        }
    }
}
