// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.Contracts.Blackbox;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class UpgradeDataGuardTests
{
    [Fact]
    public void Capture_copies_findings_history_and_identity_and_skips_rebuildable_rules()
    {
        var local = NewRoot();
        try
        {
            Write(local, @"hermes\blackbox\findings.jsonl", "one\ntwo\n");
            Write(local, @"hermes\blackbox\reporter_key.pem", "key");
            Write(local, @"Axiom\axiom.db", new string('d', 1_000));
            Write(local, @"Axiom\ai-findings.json", "[]");
            Write(local, @"Axiom\agent-evidence.jsonl", new string('e', 100));
            Write(local, @"Axiom\privacy-shield-rules.json", "rebuildable");
            Write(local, @"Axiom\modules\blackbox\agent-blackbox\.dkg\agent-key.bin", "identity");

            var backup = UpgradeDataGuard.Capture(
                local, Path.Combine(local, "backups"), new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero));

            Assert.NotNull(backup);
            Assert.True(File.Exists(Path.Combine(backup!.Directory, @"hermes\blackbox\findings.jsonl")));
            Assert.True(File.Exists(Path.Combine(backup.Directory, @"Axiom\axiom.db")));
            Assert.True(File.Exists(
                Path.Combine(backup.Directory, @"Axiom\modules\blackbox\agent-blackbox\.dkg\agent-key.bin")));
            Assert.DoesNotContain(
                backup.Entries,
                entry => entry.RelativePath.EndsWith("privacy-shield-rules.json", StringComparison.OrdinalIgnoreCase));
            Assert.Equal(6, backup.Entries.Count);
        }
        finally
        {
            Delete(local);
        }
    }

    [Fact]
    public void Verify_restores_missing_and_empty_files_and_reports_a_shrunken_file()
    {
        var local = NewRoot();
        try
        {
            Write(local, @"hermes\blackbox\findings.jsonl", "one\ntwo\n");
            Write(local, @"Axiom\ai-findings.json", "[1,2,3]");
            Write(local, @"Axiom\agent-evidence.jsonl", new string('e', 100));
            var backup = UpgradeDataGuard.Capture(
                local, Path.Combine(local, "backups"), new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero));

            var findings = Path.Combine(local, @"hermes\blackbox\findings.jsonl");
            var aiFindings = Path.Combine(local, @"Axiom\ai-findings.json");
            var evidence = Path.Combine(local, @"Axiom\agent-evidence.jsonl");
            File.Delete(findings);
            File.WriteAllText(aiFindings, string.Empty);
            File.WriteAllText(evidence, "short");

            var result = UpgradeDataGuard.VerifyAndRestore(backup!.Directory, local);

            Assert.Contains(result.Restored, path => path.EndsWith("findings.jsonl", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(result.Restored, path => path.EndsWith("ai-findings.json", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(result.Shrunk, path => path.EndsWith("agent-evidence.jsonl", StringComparison.OrdinalIgnoreCase));
            Assert.True(new FileInfo(findings).Length > 0);
            Assert.True(new FileInfo(aiFindings).Length > 0);
            Assert.Equal(5, new FileInfo(evidence).Length);
            Assert.True(result.Ok);
            Assert.True(File.Exists(Path.Combine(backup.Directory, "guard-report.json")));
        }
        finally
        {
            Delete(local);
        }
    }

    [Fact]
    public void A_file_that_grew_is_never_rewritten()
    {
        var local = NewRoot();
        try
        {
            Write(local, @"hermes\blackbox\findings.jsonl", "one\n");
            var backup = UpgradeDataGuard.Capture(
                local, Path.Combine(local, "backups"), new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero));
            var findings = Path.Combine(local, @"hermes\blackbox\findings.jsonl");
            File.AppendAllText(findings, "two\n");

            var result = UpgradeDataGuard.VerifyAndRestore(backup!.Directory, local);

            Assert.Empty(result.Restored);
            Assert.Empty(result.Shrunk);
            Assert.Equal("one\ntwo\n".Length, new FileInfo(findings).Length);
        }
        finally
        {
            Delete(local);
        }
    }

    [Fact]
    public void A_first_install_has_nothing_to_back_up()
    {
        var local = NewRoot();
        try
        {
            Directory.CreateDirectory(local);
            Assert.Null(UpgradeDataGuard.Capture(local, Path.Combine(local, "backups")));
        }
        finally
        {
            Delete(local);
        }
    }

    [Fact]
    public void Prune_keeps_the_three_newest_upgrade_backups()
    {
        var local = NewRoot();
        try
        {
            Write(local, @"hermes\blackbox\findings.jsonl", "one\n");
            var backups = Path.Combine(local, "backups");
            var start = new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);
            for (var index = 0; index < 4; index++)
            {
                UpgradeDataGuard.Capture(local, backups, start.AddMinutes(index));
            }

            var directories = Directory.GetDirectories(backups, "upgrade-*")
                .OrderByDescending(path => Path.GetFileName(path), StringComparer.Ordinal)
                .ToArray();

            Assert.Equal(UpgradeDataGuard.KeepBackups, directories.Length);
            Assert.Contains("1203", Path.GetFileName(directories[0]), StringComparison.Ordinal);
        }
        finally
        {
            Delete(local);
        }
    }

    private static string NewRoot() =>
        Path.Combine(Path.GetTempPath(), "axiom-guard-" + Guid.NewGuid().ToString("N"));

    private static void Write(string root, string relative, string content)
    {
        var path = Path.Combine(root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    private static void Delete(string root)
    {
        try
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
        catch (IOException)
        {
            // A locked temp file must not fail the test.
        }
    }
}
