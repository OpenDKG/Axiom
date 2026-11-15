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

        var protection = new DeepSeekProtection(temp.Root, temp.Root, Path.Combine(temp.Root, ".dsh"));
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
