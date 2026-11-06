// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json.Nodes;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class ZCodeProtectionTests
{
    private static readonly string[] HookNames =
        ["SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"];

    [Fact]
    public void Installs_user_scope_hooks_without_removing_existing_entries()
    {
        using var temp = new TempTree();
        var configPath = Path.Combine(temp.Root, ".zcode", "cli", "config.json");
        Directory.CreateDirectory(Path.GetDirectoryName(configPath)!);
        File.WriteAllText(configPath, """
            {
              "hooks": {
                "enabled": true,
                "events": {
                  "PreToolUse": [
                    {
                      "hooks": [
                        { "type": "command", "command": "user-check", "timeout": 5 }
                      ]
                    }
                  ]
                }
              }
            }
            """);
        CreateFakePython(temp.Root);

        var protection = new ZCodeProtection(temp.Root, temp.Root);
        Assert.True(protection.EnsureInstalled());
        Assert.True(protection.IsInstalled);

        var root = (JsonObject)JsonNode.Parse(File.ReadAllText(configPath))!;
        var events = (JsonObject)root["hooks"]!["events"]!;
        Assert.All(HookNames, name => Assert.True(events[name] is JsonArray));
        Assert.Contains(
            events["PreToolUse"]!.AsArray().OfType<JsonObject>(),
            group => group["hooks"]!.AsArray().OfType<JsonObject>()
                .Any(handler => handler["args"] is JsonArray args &&
                                args.OfType<JsonValue>().Any(value =>
                                    value.GetValue<string>() == protection.HookScriptPath)));
        Assert.Contains(
            events["PreToolUse"]!.AsArray().OfType<JsonObject>(),
            group => group["hooks"]!.AsArray().OfType<JsonObject>()
                .Any(handler => handler["command"]?.GetValue<string>() == "user-check"));

        protection.Remove();
        Assert.False(protection.IsInstalled);
        Assert.True(File.Exists(configPath));
        root = (JsonObject)JsonNode.Parse(File.ReadAllText(configPath))!;
        events = (JsonObject)root["hooks"]!["events"]!;
        Assert.Contains(
            events["PreToolUse"]!.AsArray().OfType<JsonObject>(),
            group => group["hooks"]!.AsArray().OfType<JsonObject>()
                .Any(handler => handler["command"]?.GetValue<string>() == "user-check"));
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
            Root = Path.Combine(Path.GetTempPath(), $"axiom-zcode-{Guid.NewGuid():N}");
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
