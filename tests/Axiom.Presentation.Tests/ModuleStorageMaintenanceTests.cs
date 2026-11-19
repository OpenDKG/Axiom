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
    public void RunOnce_prunes_rotated_diagnostics_without_touching_live_data()
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

            var report = ModuleStorageMaintenance.RunOnce(localAppData: local, userProfile: home);
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
            Assert.Equal(7, report.RemovedFiles);
        }
        finally
        {
            DeleteTree(root);
        }
    }

    [Fact]
    public void RunOnce_trims_hermes_and_axiom_diagnostic_logs_while_preserving_history_and_envs()
    {
        var root = NewTempRoot();
        try
        {
            var local = Path.Combine(root, "local");
            var home = Path.Combine(root, "home");

            var hermesLogs = Path.Combine(local, "hermes", "logs");
            var blackboxDir = Path.Combine(local, "hermes", "blackbox");
            var envDir = Path.Combine(local, "hermes", "installs", "abc", "environments", "old-env");
            var axiomDir = Path.Combine(local, "Axiom");
            Directory.CreateDirectory(hermesLogs);
            Directory.CreateDirectory(blackboxDir);
            Directory.CreateDirectory(envDir);
            Directory.CreateDirectory(axiomDir);

            var errorsLog = Path.Combine(hermesLogs, "errors.log");
            var recoveryLog = Path.Combine(axiomDir, "network-recovery.log");
            var findings = Path.Combine(blackboxDir, "findings.jsonl");
            var envMarker = Path.Combine(envDir, "marker.txt");

            // Exceed 5 MiB for errors.log and 2 MiB for network-recovery.log.
            var line = new string('E', 1023) + "\n";
            File.WriteAllText(errorsLog, string.Concat(Enumerable.Repeat(line, 5600)));
            File.WriteAllText(recoveryLog, string.Concat(Enumerable.Repeat(line, 2300)));
            File.WriteAllText(findings, "{\"id\":1}\n");
            File.WriteAllText(envMarker, "keep");

            var report = ModuleStorageMaintenance.RunOnce(localAppData: local, userProfile: home);

            Assert.Equal(2, report.TrimmedLogs);
            Assert.True(report.ReclaimedBytes > 5L * 1024 * 1024);
            Assert.True(new FileInfo(errorsLog).Length <= 1L * 1024 * 1024);
            Assert.True(new FileInfo(recoveryLog).Length <= 512L * 1024);
            Assert.Equal("{\"id\":1}\n", File.ReadAllText(findings));
            Assert.True(File.Exists(envMarker));
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
