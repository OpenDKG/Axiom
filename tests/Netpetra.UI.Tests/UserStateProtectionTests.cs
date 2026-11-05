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

    private sealed class TempTree : IDisposable
    {
        public TempTree()
        {
            Root = Path.Combine(Path.GetTempPath(), $"netpetra-user-state-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

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
