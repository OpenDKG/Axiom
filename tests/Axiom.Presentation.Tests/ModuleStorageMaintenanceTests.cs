// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class ModuleStorageMaintenanceTests
{
    [Fact]
    public void EnsureOxigraphWalMaintenance_sets_threshold_and_preserves_existing_fields()
    {
        var root = NewTempRoot();
        try
        {
            var configPath = Path.Combine(root, "config.json");
            File.WriteAllText(
                configPath,
                """
                {
                  "name": "agent-blackbox",
                  "apiPort": 9320,
                  "store": {
                    "backend": "oxigraph-server",
                    "options": {
                      "port": 7879
                    }
                  }
                }
                """);

            var updated = ModuleStorageMaintenance.EnsureOxigraphWalMaintenance(configPath);
            Assert.True(updated);

            using var doc = JsonDocument.Parse(File.ReadAllText(configPath));
            Assert.Equal("agent-blackbox", doc.RootElement.GetProperty("name").GetString());
            Assert.Equal(9320, doc.RootElement.GetProperty("apiPort").GetInt32());
            var options = doc.RootElement.GetProperty("store").GetProperty("options");
            Assert.Equal(7879, options.GetProperty("port").GetInt32());
            Assert.Equal(
                ModuleStorageMaintenance.DefaultOxigraphWalRestartThresholdBytes,
                options.GetProperty("walRestartThresholdBytes").GetInt64());

            // Second call is a no-op once the threshold is already present.
            Assert.False(ModuleStorageMaintenance.EnsureOxigraphWalMaintenance(configPath));
        }
        finally
        {
            DeleteTree(root);
        }
    }

    [Fact]
    public void EnsureOxigraphWalMaintenance_preserves_stricter_threshold_and_ignores_other_backends()
    {
        var root = NewTempRoot();
        try
        {
            var strictPath = Path.Combine(root, "strict.json");
            File.WriteAllText(
                strictPath,
                """
                {
                  "store": {
                    "backend": "oxigraph-server",
                    "options": {
                      "port": 7879,
                      "walRestartThresholdBytes": 134217728
                    }
                  }
                }
                """);

            Assert.False(ModuleStorageMaintenance.EnsureOxigraphWalMaintenance(strictPath));
            using (var doc = JsonDocument.Parse(File.ReadAllText(strictPath)))
            {
                Assert.Equal(
                    134_217_728L,
                    doc.RootElement.GetProperty("store").GetProperty("options").GetProperty("walRestartThresholdBytes").GetInt64());
            }

            var otherPath = Path.Combine(root, "other.json");
            File.WriteAllText(
                otherPath,
                """
                {
                  "store": {
                    "backend": "blazegraph",
                    "options": { "url": "http://127.0.0.1:9999" }
                  }
                }
                """);

            Assert.False(ModuleStorageMaintenance.EnsureOxigraphWalMaintenance(otherPath));
        }
        finally
        {
            DeleteTree(root);
        }
    }

    [Fact]
    public void TrimFileInPlace_preserves_newest_lines_aligned_to_newline_boundary()
    {
        var root = NewTempRoot();
        try
        {
            var logPath = Path.Combine(root, "audit.jsonl");
            var lines = Enumerable.Range(1, 500)
                .Select(i => $"{{\"seq\":{i},\"msg\":\"entry-{i:D4}-payload\"}}")
                .ToArray();
            File.WriteAllText(logPath, string.Join('\n', lines) + "\n");
            var originalLength = new FileInfo(logPath).Length;

            var reclaimed = ModuleStorageMaintenance.TrimFileInPlace(logPath, maxBytes: 4096, keepBytes: 1024);

            Assert.True(reclaimed > 0);
            var trimmedText = File.ReadAllText(logPath);
            Assert.True(new FileInfo(logPath).Length < originalLength);
            Assert.True(new FileInfo(logPath).Length <= 1024);
            Assert.EndsWith("{\"seq\":500,\"msg\":\"entry-0500-payload\"}\n", trimmedText, StringComparison.Ordinal);

            // Every remaining line must still be valid JSON (no mid-line truncation).
            foreach (var line in trimmedText.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                using var parsed = JsonDocument.Parse(line);
                Assert.True(parsed.RootElement.TryGetProperty("seq", out _));
            }
        }
        finally
        {
            DeleteTree(root);
        }
    }

    [Fact]
    public void RunOnce_prunes_orphaned_hermes_environments_while_keeping_active_and_recent()
    {
        var root = NewTempRoot();
        try
        {
            var local = Path.Combine(root, "local");
            var home = Path.Combine(root, "home");
            var now = new DateTimeOffset(2026, 11, 19, 18, 0, 0, TimeSpan.Zero);

            var activeInstall = Path.Combine(local, "hermes", "installs", "active-install");
            var activeEnvDir = Path.Combine(activeInstall, "environments", "env-active");
            var activeVenv = Path.Combine(activeEnvDir, "venv");
            var oldEnvDir = Path.Combine(activeInstall, "environments", "env-stale");
            var recentEnvDir = Path.Combine(activeInstall, "environments", "env-recent");
            var abandonedInstall = Path.Combine(local, "hermes", "installs", "abandoned-install");

            Directory.CreateDirectory(activeVenv);
            Directory.CreateDirectory(oldEnvDir);
            Directory.CreateDirectory(recentEnvDir);
            Directory.CreateDirectory(abandonedInstall);

            File.WriteAllText(Path.Combine(activeVenv, "keep.txt"), "active");
            File.WriteAllText(Path.Combine(oldEnvDir, "stale.bin"), new string('x', 4096));
            File.WriteAllText(Path.Combine(recentEnvDir, "recent.bin"), new string('y', 1024));
            File.WriteAllText(Path.Combine(abandonedInstall, "old.bin"), new string('z', 2048));

            var factsPath = Path.Combine(activeInstall, "facts.json");
            File.WriteAllText(
                factsPath,
                JsonSerializer.Serialize(new
                {
                    packages = new
                    {
                        venv = new { environment = activeVenv },
                    },
                }));

            Directory.SetLastWriteTimeUtc(oldEnvDir, now.AddHours(-5).UtcDateTime);
            Directory.SetLastWriteTimeUtc(recentEnvDir, now.AddMinutes(-10).UtcDateTime);
            Directory.SetLastWriteTimeUtc(abandonedInstall, now.AddDays(-5).UtcDateTime);
            File.SetLastWriteTimeUtc(factsPath, now.AddHours(-2).UtcDateTime);

            var report = ModuleStorageMaintenance.RunOnce(
                localAppData: local,
                userProfile: home,
                nowUtc: now);

            Assert.True(Directory.Exists(activeEnvDir));
            Assert.True(Directory.Exists(recentEnvDir));
            Assert.False(Directory.Exists(oldEnvDir));
            Assert.False(Directory.Exists(abandonedInstall));
            Assert.Equal(2, report.RemovedDirectories);
            Assert.True(report.ReclaimedBytes >= 6144);
        }
        finally
        {
            DeleteTree(root);
        }
    }

    [Fact]
    public void RunOnce_cleans_old_logs_temps_and_legacy_backups_without_touching_live_data()
    {
        var root = NewTempRoot();
        try
        {
            var local = Path.Combine(root, "local");
            var home = Path.Combine(root, "home");
            var now = new DateTimeOffset(2026, 11, 19, 18, 0, 0, TimeSpan.Zero);

            var dkgHome = Path.Combine(local, "hermes", "blackbox", "node", ".dkg");
            var oxiData = Path.Combine(dkgHome, "oxigraph-data");
            Directory.CreateDirectory(oxiData);
            File.WriteAllText(
                Path.Combine(dkgHome, "config.json"),
                """{"store":{"backend":"oxigraph-server","options":{"port":7879}}}""");

            // Active RocksDB files must never be removed.
            var activeWal = Path.Combine(oxiData, "004500.log");
            var activeSst = Path.Combine(oxiData, "000100.sst");
            var activeInfoLog = Path.Combine(oxiData, "LOG");
            File.WriteAllText(activeWal, "wal");
            File.WriteAllText(activeSst, "sst");
            File.WriteAllText(activeInfoLog, "info");

            // 15 rotated RocksDB diagnostic text logs -> keep 10, delete 5 oldest.
            for (var i = 1; i <= 15; i++)
            {
                var path = Path.Combine(oxiData, $"LOG.old.{i:D6}");
                File.WriteAllText(path, new string('L', 256));
                File.SetLastWriteTimeUtc(path, now.AddMinutes(-100 + i).UtcDateTime);
            }

            // DKG daemon.log + .1, .2, .3, .4 -> keep live + .1 + .2, delete .3 and .4.
            File.WriteAllText(Path.Combine(dkgHome, "daemon.log"), "live");
            for (var i = 1; i <= 4; i++)
            {
                File.WriteAllText(Path.Combine(dkgHome, $"daemon.log.{i}"), new string('D', 512));
            }

            // Stale temp file in hermes\blackbox and legacy service-backup-*.exe in Axiom.
            var blackboxDir = Path.Combine(local, "hermes", "blackbox");
            var staleTmp = Path.Combine(blackboxDir, "community-pulse.stamp.tmp.1234.abcd");
            var freshTmp = Path.Combine(blackboxDir, "community-pulse.stamp.tmp.9999.efgh");
            File.WriteAllText(staleTmp, "stale");
            File.WriteAllText(freshTmp, "fresh");
            File.SetLastWriteTimeUtc(staleTmp, now.AddDays(-2).UtcDateTime);
            File.SetLastWriteTimeUtc(freshTmp, now.AddMinutes(-5).UtcDateTime);

            var axiomDir = Path.Combine(local, "Axiom");
            Directory.CreateDirectory(axiomDir);
            var legacyBackup = Path.Combine(axiomDir, "service-backup-0.2.0.exe");
            File.WriteAllText(legacyBackup, new string('S', 2048));
            File.SetLastWriteTimeUtc(legacyBackup, now.AddDays(-3).UtcDateTime);

            var report = ModuleStorageMaintenance.RunOnce(
                localAppData: local,
                userProfile: home,
                nowUtc: now);

            Assert.Equal(1, report.DkgConfigsUpdated);
            Assert.True(File.Exists(activeWal));
            Assert.True(File.Exists(activeSst));
            Assert.True(File.Exists(activeInfoLog));
            Assert.Equal(
                ModuleStorageMaintenance.KeepOxigraphOldInfoLogs,
                Directory.GetFiles(oxiData, "LOG.old.*").Length);
            Assert.True(File.Exists(Path.Combine(dkgHome, "daemon.log")));
            Assert.True(File.Exists(Path.Combine(dkgHome, "daemon.log.1")));
            Assert.True(File.Exists(Path.Combine(dkgHome, "daemon.log.2")));
            Assert.False(File.Exists(Path.Combine(dkgHome, "daemon.log.3")));
            Assert.False(File.Exists(Path.Combine(dkgHome, "daemon.log.4")));
            Assert.False(File.Exists(staleTmp));
            Assert.True(File.Exists(freshTmp));
            Assert.False(File.Exists(legacyBackup));
            Assert.Equal(9, report.RemovedFiles); // 5 LOG.old + 2 daemon.log + 1 staleTmp + 1 legacyBackup
        }
        finally
        {
            DeleteTree(root);
        }
    }

    private static string NewTempRoot()
    {
        var path = Path.Combine(Path.GetTempPath(), "axiom-storage-maint-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void DeleteTree(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
        }
    }
}
