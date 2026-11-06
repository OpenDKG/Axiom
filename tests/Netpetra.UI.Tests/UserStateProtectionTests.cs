// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Netpetra.UI.Services;
using Xunit;

namespace Netpetra.UI.Tests;

public sealed class UserStateProtectionTests
{
    [Fact]
    public void Unexpected_config_change_is_detected_and_restored()
    {
        using var temp = new TempTree();
        var config = Path.Combine(temp.Root, ".config", "opencode", "opencode.json");
        Directory.CreateDirectory(Path.GetDirectoryName(config)!);
        File.WriteAllText(config, """{"model":"user-model","mcpServers":{}}""");

        var protection = new UserStateProtection(temp.Root, temp.Root, temp.Root);
        var snapshot = protection.Capture();
        File.WriteAllText(config, """{"model":"changed","mcpServers":{}}""");

        var changes = protection.Verify(snapshot, []);
        Assert.Contains(changes, change => change.Path == config);
        Assert.Empty(protection.Restore(snapshot, changes));
        Assert.Equal("""{"model":"user-model","mcpServers":{}}""", File.ReadAllText(config));
    }

    [Fact]
    public void Unreadable_protected_file_is_not_deleted_by_restore()
    {
        using var temp = new TempTree();
        var config = Path.Combine(temp.Root, ".codex", "auth.json");
        Directory.CreateDirectory(Path.GetDirectoryName(config)!);
        File.WriteAllText(config, "user-secret");

        var protection = new UserStateProtection(temp.Root, temp.Root, temp.Root);
        UserStateSnapshot snapshot;
        using (new FileStream(config, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            snapshot = protection.Capture();
        }

        Assert.True(snapshot.Files[config].CaptureFailed);

        var failures = protection.Restore(
            snapshot,
            [new UserStateChange(config, "content changed")]);

        Assert.Contains(config, failures);
        Assert.True(File.Exists(config));
        Assert.Equal("user-secret", File.ReadAllText(config));
    }

    [Fact]
    public void Explicitly_allowed_hook_path_is_ignored()
    {
        using var temp = new TempTree();
        var hooks = Path.Combine(temp.Root, ".codex", "hooks.json");
        Directory.CreateDirectory(Path.GetDirectoryName(hooks)!);
        File.WriteAllText(hooks, "{}");

        var protection = new UserStateProtection(temp.Root, temp.Root, temp.Root);
        var snapshot = protection.Capture();
        File.WriteAllText(hooks, """{"hooks":{}}""");

        Assert.Empty(protection.Verify(snapshot, [hooks]));
    }

    [Fact]
    public void Antigravity_history_directory_removal_is_detected()
    {
        using var temp = new TempTree();
        var antigravity = Path.Combine(temp.Root, ".gemini", "antigravity");
        Directory.CreateDirectory(Path.Combine(antigravity, "conversations"));
        File.WriteAllText(Path.Combine(antigravity, "conversation_summaries.db"), "history");

        var protection = new UserStateProtection(temp.Root, temp.Root, temp.Root);
        var snapshot = protection.Capture();
        Directory.Delete(antigravity, recursive: true);

        var changes = protection.Verify(snapshot, []);
        Assert.Contains(changes, change => change.Path == antigravity);
        Assert.Contains(changes, change =>
            change.Path.EndsWith("conversation_summaries.db", StringComparison.Ordinal));
    }

    [Fact]
    public void Nested_antigravity_conversation_change_is_detected()
    {
        using var temp = new TempTree();
        var conversation = Path.Combine(
            temp.Root,
            ".gemini",
            "antigravity",
            "conversations",
            "session.db");
        Directory.CreateDirectory(Path.GetDirectoryName(conversation)!);
        File.WriteAllText(conversation, "user conversation");

        var protection = new UserStateProtection(temp.Root, temp.Root, temp.Root);
        var snapshot = protection.Capture();
        File.WriteAllText(conversation, "replaced conversation");

        var changes = protection.Verify(snapshot, []);
        Assert.Contains(changes, change => change.Path == conversation);
    }

    [Fact]
    public void Large_antigravity_database_change_is_detected()
    {
        using var temp = new TempTree();
        var database = Path.Combine(temp.Root, ".gemini", "antigravity", "conversation_summaries.db");
        Directory.CreateDirectory(Path.GetDirectoryName(database)!);
        var content = new byte[(1024 * 1024) + 1];
        File.WriteAllBytes(database, content);

        var protection = new UserStateProtection(temp.Root, temp.Root, temp.Root);
        var snapshot = protection.Capture();
        content[0] = 1;
        File.WriteAllBytes(database, content);

        var changes = protection.Verify(snapshot, []);
        Assert.Contains(changes, change => change.Path == database);
    }

    [Fact]
    public void Protection_inventory_covers_sessions_projects_credentials_and_databases()
    {
        using var temp = new TempTree();
        var protection = new UserStateProtection(temp.Root, temp.Root, temp.Root);
        var files = protection.ProtectedFiles.Select(spec => spec.Path).ToArray();
        var directories = protection.ProtectedDirectories.Select(spec => spec.Path).ToArray();

        Assert.Contains(Path.Combine(temp.Root, ".local", "share", "opencode", "auth.json"), files);
        Assert.Contains(Path.Combine(temp.Root, ".local", "share", "opencode", "opencode.db"), files);
        Assert.Contains(Path.Combine(temp.Root, ".codex", "auth.json"), files);
        Assert.Contains(Path.Combine(temp.Root, ".codex", "thread_history_1.sqlite"), files);
        Assert.Contains(Path.Combine(temp.Root, ".config", "openchamber", "projects"), directories);
        Assert.Contains(Path.Combine(temp.Root, ".codex", "sessions"), directories);
        Assert.Contains(Path.Combine(temp.Root, ".claude"), directories);
        Assert.Contains(Path.Combine(temp.Root, ".gemini", "antigravity", "conversations"), directories);
        Assert.Contains(Path.Combine(temp.LocalAppData, "hermes", "sessions"), directories);
        Assert.Contains(Path.Combine(temp.RoamingAppData, "Cursor", "User", "globalStorage", "state.vscdb"), files);
        Assert.Contains(Path.Combine(temp.LocalAppData, "Netpetra", "privacy-shield.json"), files);
    }

    [Fact]
    public void Metadata_only_database_change_is_detected()
    {
        using var temp = new TempTree();
        var database = Path.Combine(temp.Root, ".local", "share", "opencode", "opencode.db");
        Directory.CreateDirectory(Path.GetDirectoryName(database)!);
        File.WriteAllText(database, "database");

        var protection = new UserStateProtection(temp.Root, temp.Root, temp.Root);
        var snapshot = protection.Capture();
        File.AppendAllText(database, " changed");

        var changes = protection.Verify(snapshot, []);
        Assert.Contains(changes, change => change.Path == database);
    }

    [Fact]
    public void Unchanged_protected_state_has_no_changes()
    {
        using var temp = new TempTree();
        var files = new[]
        {
            Path.Combine(temp.Root, ".config", "opencode", "opencode.json"),
            Path.Combine(temp.Root, ".local", "share", "opencode", "opencode.db"),
            Path.Combine(temp.Root, ".gemini", "antigravity", "conversations", "session.db"),
            Path.Combine(temp.Root, "hermes", "sessions", "session.json"),
            Path.Combine(temp.Root, "Netpetra", "reputation.json"),
        };
        foreach (var file in files)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            File.WriteAllText(file, "unchanged");
        }

        var protection = new UserStateProtection(temp.Root, temp.Root, temp.Root);
        var snapshot = protection.Capture();

        Assert.Empty(protection.Verify(snapshot, []));
    }

    [Fact]
    public void OpenCode_first_install_creates_only_allowed_hook_changes()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".config", "opencode"));
        var python = Path.Combine(
            temp.Root,
            "Netpetra",
            "modules",
            "blackbox",
            "agent-blackbox",
            "venv",
            "Scripts",
            "python.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(python)!);
        File.WriteAllText(python, string.Empty);

        var protection = new UserStateProtection(temp.Root, temp.Root, temp.Root);
        var snapshot = protection.Capture();
        var openCode = new OpenCodeProtection(temp.Root, temp.Root, temp.Root);
        Assert.True(openCode.EnsureInstalled());

        Assert.Empty(protection.Verify(
            snapshot,
            [openCode.PluginPath, openCode.V1PluginPath, openCode.LegacyPluginPath, openCode.BridgePath]));
    }

    [Fact]
    public void Codex_hook_install_creates_only_the_allowed_hook_change()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".codex"));
        var python = Path.Combine(
            temp.Root,
            "Netpetra",
            "modules",
            "blackbox",
            "agent-blackbox",
            "venv",
            "Scripts",
            "python.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(python)!);
        File.WriteAllText(python, string.Empty);

        var protection = new UserStateProtection(temp.Root, temp.Root, temp.Root);
        var snapshot = protection.Capture();
        var codex = new CodexProtection(temp.Root, temp.Root);
        Assert.True(codex.EnsureInstalled());

        Assert.Empty(protection.Verify(snapshot, [codex.HooksPath]));
    }

    [Fact]
    public void Explicitly_allowed_uninstall_deletion_is_ignored()
    {
        using var temp = new TempTree();
        var settings = Path.Combine(temp.Root, "Netpetra", "reputation.json");
        Directory.CreateDirectory(Path.GetDirectoryName(settings)!);
        File.WriteAllText(settings, "secret");

        var protection = new UserStateProtection(temp.Root, temp.Root, temp.Root);
        var snapshot = protection.Capture();
        File.Delete(settings);

        Assert.Empty(protection.Verify(snapshot, [settings]));
    }

    [Fact]
    public void Netpetra_backup_files_are_not_treated_as_user_state_changes()
    {
        using var temp = new TempTree();
        var hooks = Path.Combine(temp.Root, ".codex", "hooks.json");
        Directory.CreateDirectory(Path.GetDirectoryName(hooks)!);
        File.WriteAllText(hooks, "{}");

        var protection = new UserStateProtection(temp.Root, temp.Root, temp.Root);
        var snapshot = protection.Capture();
        File.WriteAllText(hooks + ".netpetra-backup-20261105", "{}");

        Assert.Empty(protection.Verify(snapshot, []));
    }

    [Fact]
    public void Explicit_installer_owned_paths_can_be_allowed()
    {
        using var temp = new TempTree();
        var config = Path.Combine(temp.LocalAppData, "hermes", "config.yaml");
        Directory.CreateDirectory(Path.GetDirectoryName(config)!);
        File.WriteAllText(config, "plugins: {}\n");

        var protection = new UserStateProtection(temp.Root, temp.Root, temp.Root);
        var snapshot = protection.Capture();
        File.WriteAllText(config, "plugins: {entries: {blackbox: {mode: block}}}\n");

        Assert.Empty(protection.Verify(snapshot, [config]));
    }

    private sealed class TempTree : IDisposable
    {
        public TempTree()
        {
            Root = Path.Combine(Path.GetTempPath(), $"netpetra-user-state-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public string LocalAppData => Root;

        public string RoamingAppData => Root;

        public void Dispose()
        {
            try
            {
                Directory.Delete(Root, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
