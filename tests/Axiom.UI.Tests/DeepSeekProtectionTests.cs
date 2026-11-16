// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json.Nodes;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class DeepSeekProtectionTests
{
    private static readonly string[] HookNames =
        ["SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"];

    [Fact]
    public void Prepares_hooks_and_bridge_mount_and_requires_the_bridge_package()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".dsh"));
        CreateFakePython(temp.Root);

        var protection = new DeepSeekProtection(
            temp.Root,
            temp.Root,
            Path.Combine(temp.Root, ".dsh"),
            Path.Combine(temp.Root, "npm", "node_modules"));
        Assert.False(protection.EnsureInstalled());
        Assert.True(protection.IsConfigured);
        Assert.True(File.Exists(protection.HooksPath));
        Assert.False(protection.IsBridgeInstalled);
        Assert.False(protection.IsInstalled);

        var hooks = (JsonObject)JsonNode.Parse(File.ReadAllText(protection.HooksPath))!;
        Assert.All(HookNames, name => Assert.True(hooks[name] is JsonArray));
        Assert.Contains(
            hooks["PreToolUse"]!.AsArray().OfType<JsonObject>(),
            group => group["hooks"]!.AsArray().OfType<JsonObject>()
                .Any(handler => handler["command"]?.GetValue<string>()?.Contains(
                    protection.HookScriptPath,
                    StringComparison.Ordinal) == true));
        Assert.Contains("dsh-hooks-claude-code", File.ReadAllText(protection.PatchPath), StringComparison.Ordinal);

        var bridge = Path.Combine(
            protection.DshHome,
            "profiles",
            "web",
            "node_modules",
            "@deepseek-ai",
            "dsh-hooks-claude-code");
        Directory.CreateDirectory(bridge);
        File.WriteAllText(Path.Combine(bridge, "package.json"), "{}");
        Assert.True(protection.IsInstalled);

        protection.Remove();
        Assert.False(File.Exists(protection.HooksPath));
        Assert.False(File.Exists(protection.PatchPath));
    }

    [Fact]
    public void IsDeepSeekAvailable_ignores_hookless_deepseek_cli_and_skips_orphaned_hook_provisioning()
    {
        // #353: deepseek-cli on npm installs a `deepseek` command with no hook surface.
        Assert.False(AgentBinaryLocator.IsDeepSeekAvailable(
            name => string.Equals(name, "deepseek", StringComparison.OrdinalIgnoreCase),
            _ => false));
        Assert.True(AgentBinaryLocator.IsDeepSeekAvailable(
            name => string.Equals(name, "dsh", StringComparison.OrdinalIgnoreCase),
            _ => false));

        using var temp = new TempTree();
        CreateFakePython(temp.Root);
        var protection = new DeepSeekProtection(temp.Root, temp.Root, Path.Combine(temp.Root, ".dsh"));
        if (!AgentBinaryLocator.IsDeepSeekAvailable())
        {
            Assert.False(protection.IsDeepSeekDetected);
            Assert.False(protection.EnsureInstalled());
            Assert.False(File.Exists(protection.HookScriptPath));
            Assert.False(File.Exists(protection.HooksPath));
            Assert.False(File.Exists(protection.PatchPath));
        }
    }

    [Fact]
    public void Mismatched_bridge_version_is_not_reported_as_protection()
    {
        // #369: dsh plugin add rejects a bridge built for another dsh release, so a present
        // package alone must not make Axiom claim DeepSeek is protected.
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".dsh"));
        CreateFakePython(temp.Root);

        var npm = Path.Combine(temp.Root, "npm", "node_modules");
        var protection = new DeepSeekProtection(
            temp.Root,
            temp.Root,
            Path.Combine(temp.Root, ".dsh"),
            npm);
        protection.EnsureInstalled();
        Assert.True(protection.IsConfigured);

        WritePackage(Path.Combine(npm, "@deepseek-ai", "dsh"), "0.2.2-rc.1", ">= 24.9.0");
        var bridge = Path.Combine(
            protection.DshHome,
            "profiles",
            "web",
            "node_modules",
            "@deepseek-ai",
            "dsh-hooks-claude-code");
        WritePackage(bridge, "0.0.1-rc.5", null);

        Assert.True(protection.IsBridgeInstalled);
        Assert.Equal("0.0.1-rc.5", protection.BridgeVersion);
        Assert.Equal("0.2.2-rc.1", protection.RuntimeVersion);
        Assert.False(protection.IsBridgeCompatible);
        Assert.Contains("0.0.1-rc.5", protection.BridgeVersionMismatch!, StringComparison.Ordinal);
        Assert.False(protection.IsInstalled);

        WritePackage(bridge, "0.2.2-rc.1", null);
        Assert.True(protection.IsBridgeCompatible);
        Assert.Null(protection.BridgeVersionMismatch);
        Assert.True(protection.IsInstalled);
    }

    [Fact]
    public void Bridge_and_node_version_checks_compare_numerically_and_keep_unknown_versions()
    {
        Assert.True(DeepSeekProtection.BridgeVersionMatches("v0.2.2-rc.3", "0.2.2-RC.3"));
        Assert.False(DeepSeekProtection.BridgeVersionMatches("0.0.1-rc.5", "0.2.2-rc.1"));
        Assert.True(DeepSeekProtection.BridgeVersionMatches(null, "0.2.2-rc.1"));
        Assert.True(DeepSeekProtection.BridgeVersionMatches("0.2.2-rc.1", null));

        Assert.True(DeepSeekProtection.NodeSatisfies("24.9.0", ">= 24.9.0"));
        Assert.True(DeepSeekProtection.NodeSatisfies("24.10.1", ">= 24.9.0"));
        Assert.False(DeepSeekProtection.NodeSatisfies("22.23.5", ">= 24.9.0"));
        Assert.True(DeepSeekProtection.NodeSatisfies(null, ">= 24.9.0"));
        Assert.True(DeepSeekProtection.NodeSatisfies("22.23.5", null));
    }

    private static void WritePackage(string root, string version, string? nodeEngine)
    {
        Directory.CreateDirectory(root);
        var manifest = new JsonObject { ["version"] = version };
        if (nodeEngine is not null)
        {
            manifest["engines"] = new JsonObject { ["node"] = nodeEngine };
        }

        File.WriteAllText(Path.Combine(root, "package.json"), manifest.ToJsonString());
    }

    private static void CreateFakePython(string root)
    {
        var python = Path.Combine(
            root,
            "Axiom",
            "modules",
            "blackbox",
            "agent-blackbox",
            "venv",
            "Scripts",
            "python.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(python)!);
        File.WriteAllText(python, string.Empty);
    }

    private sealed class TempTree : IDisposable
    {
        public TempTree()
        {
            Root = Path.Combine(Path.GetTempPath(), $"axiom-deepseek-{Guid.NewGuid():N}");
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
