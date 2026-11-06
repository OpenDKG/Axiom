// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json.Nodes;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class CodexTrustTests
{
    [Fact]
    public void ComputeHash_matches_Codex_persisted_identity()
    {
        var group = new JsonObject
        {
            ["matcher"] = "*",
            ["hooks"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "command",
                    ["command"] = @"C:\Tools\python.exe C:\Tools\hook.py",
                    ["timeout"] = 30,
                },
            },
        };
        var handler = (JsonObject)group["hooks"]![0]!;

        var hash = CodexTrustInspector.ComputeHash(group, handler, "pre_tool_use");

        Assert.Equal("sha256:3c37619d2c6ba3c9e7a65b9608147cd78b3a7cc8c0c1046bdfd0bd4ed23aee27", hash);
    }

    [Fact]
    public void Trust_is_true_only_when_every_current_lifecycle_hook_is_trusted()
    {
        using var temp = new TempTree();
        CreateFakePython(temp.Root);
        Directory.CreateDirectory(Path.Combine(temp.Root, ".codex"));
        var protection = new CodexProtection(temp.Root, temp.Root);
        Assert.True(protection.IsCodexDetected, "Codex not detected");
        Assert.True(protection.EnsureInstalled(),
            File.Exists(protection.HooksPath) ? File.ReadAllText(protection.HooksPath) : "hooks.json missing");

        var hashes = CurrentHashes(protection.HooksPath);
        Assert.Equal(5, hashes.Count);
        WriteState(protection.ConfigPath, hashes);

        var trusted = protection.TrustState;
        Assert.True(trusted.Trusted);
        Assert.False(trusted.TrustRequired);

        WriteState(protection.ConfigPath, hashes.Where(pair => pair.Key != "stop").ToDictionary());
        var missing = protection.TrustState;
        Assert.False(missing.Trusted);
        Assert.True(missing.TrustRequired);

        var disabled = new Dictionary<string, string>(hashes);
        WriteState(protection.ConfigPath, disabled, disabledEvent: "pre_tool_use");
        var rejected = protection.TrustState;
        Assert.False(rejected.Trusted);
        Assert.True(rejected.TrustRequired);
    }

    [Fact]
    public void Changing_the_hook_definition_requires_fresh_trust()
    {
        using var temp = new TempTree();
        CreateFakePython(temp.Root);
        Directory.CreateDirectory(Path.Combine(temp.Root, ".codex"));
        var protection = new CodexProtection(temp.Root, temp.Root);
        Assert.True(protection.EnsureInstalled());
        WriteState(protection.ConfigPath, CurrentHashes(protection.HooksPath));
        Assert.True(protection.TrustState.Trusted);

        var root = JsonNode.Parse(File.ReadAllText(protection.HooksPath)) as JsonObject;
        var pre = (JsonObject)root!["hooks"]!["PreToolUse"]![0]!;
        var handler = (JsonObject)pre["hooks"]![0]!;
        handler["command"] = handler["command"]!.GetValue<string>() + " --changed";
        handler["commandWindows"] = handler["commandWindows"]!.GetValue<string>() + " --changed";
        File.WriteAllText(protection.HooksPath, root.ToJsonString());

        var state = protection.TrustState;
        Assert.False(state.Trusted);
        Assert.True(state.TrustRequired);
    }

    private static Dictionary<string, string> CurrentHashes(string hooksPath)
    {
        var root = (JsonObject)JsonNode.Parse(File.ReadAllText(hooksPath))!;
        var hooks = (JsonObject)root["hooks"]!;
        var eventKeys = new Dictionary<string, string>
        {
            ["SessionStart"] = "session_start",
            ["UserPromptSubmit"] = "user_prompt_submit",
            ["PreToolUse"] = "pre_tool_use",
            ["PostToolUse"] = "post_tool_use",
            ["Stop"] = "stop",
        };
        var result = new Dictionary<string, string>();
        foreach (var (eventName, eventKey) in eventKeys)
        {
            var group = hooks[eventName]!.AsArray().OfType<JsonObject>()
                .First(item => item["hooks"]!.AsArray().OfType<JsonObject>()
                    .Any(handler => handler["command"]?.GetValue<string>().Contains("axiom-codex-hook.py", StringComparison.Ordinal) == true));
            var handler = group["hooks"]!.AsArray().OfType<JsonObject>()
                .First(item => item["command"]?.GetValue<string>().Contains("axiom-codex-hook.py", StringComparison.Ordinal) == true);
            result[eventKey] = CodexTrustInspector.ComputeHash(group, handler, eventKey);
        }

        return result;
    }

    private static void WriteState(
        string path,
        IReadOnlyDictionary<string, string> hashes,
        string? disabledEvent = null)
    {
        var lines = new List<string>();
        foreach (var (eventKey, hash) in hashes)
        {
            lines.Add($"[hooks.state.'C:\\Users\\test\\.codex\\hooks.json:{eventKey}:0:0']");
            lines.Add($"trusted_hash = \"{hash}\"");
            if (string.Equals(eventKey, disabledEvent, StringComparison.Ordinal))
            {
                lines.Add("enabled = false");
            }

            lines.Add(string.Empty);
        }

        File.WriteAllText(path, string.Join('\n', lines));
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
            Root = Path.Combine(Path.GetTempPath(), $"axiom-codex-trust-{Guid.NewGuid():N}");
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
